rule TTP_XOR_QUAD_CurrentVersionRun_16ff {
  strings:
    $key_16ff = { 45 90 [2] 61 9e [2] 4a b2 [2] 64 90 [2] 70 8b [2] 7f 91 [2] 61 8c [2] 63 8d [2] 78 8b [2] 64 8c [2] 78 a3 }

  condition:
    any of them
}