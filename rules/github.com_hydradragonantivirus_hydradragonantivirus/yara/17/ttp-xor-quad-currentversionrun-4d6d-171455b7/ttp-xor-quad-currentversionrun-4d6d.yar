rule TTP_XOR_QUAD_CurrentVersionRun_4d6d {
  strings:
    $key_4d6d = { 1e 02 [2] 3a 0c [2] 11 20 [2] 3f 02 [2] 2b 19 [2] 24 03 [2] 3a 1e [2] 38 1f [2] 23 19 [2] 3f 1e [2] 23 31 }

  condition:
    any of them
}