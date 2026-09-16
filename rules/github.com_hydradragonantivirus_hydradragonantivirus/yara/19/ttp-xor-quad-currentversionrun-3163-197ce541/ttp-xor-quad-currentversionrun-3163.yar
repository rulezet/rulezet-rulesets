rule TTP_XOR_QUAD_CurrentVersionRun_3163 {
  strings:
    $key_3163 = { 62 0c [2] 46 02 [2] 6d 2e [2] 43 0c [2] 57 17 [2] 58 0d [2] 46 10 [2] 44 11 [2] 5f 17 [2] 43 10 [2] 5f 3f }

  condition:
    any of them
}