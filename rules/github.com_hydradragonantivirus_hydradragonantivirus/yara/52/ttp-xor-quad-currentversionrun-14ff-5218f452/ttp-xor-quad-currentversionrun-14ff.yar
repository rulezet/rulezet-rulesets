rule TTP_XOR_QUAD_CurrentVersionRun_14ff {
  strings:
    $key_14ff = { 47 90 [2] 63 9e [2] 48 b2 [2] 66 90 [2] 72 8b [2] 7d 91 [2] 63 8c [2] 61 8d [2] 7a 8b [2] 66 8c [2] 7a a3 }

  condition:
    any of them
}