rule TTP_XOR_QUAD_CurrentVersionRun_56ff {
  strings:
    $key_56ff = { 05 90 [2] 21 9e [2] 0a b2 [2] 24 90 [2] 30 8b [2] 3f 91 [2] 21 8c [2] 23 8d [2] 38 8b [2] 24 8c [2] 38 a3 }

  condition:
    any of them
}