rule TTP_XOR_QUAD_CurrentVersionRun_3150 {
  strings:
    $key_3150 = { 62 3f [2] 46 31 [2] 6d 1d [2] 43 3f [2] 57 24 [2] 58 3e [2] 46 23 [2] 44 22 [2] 5f 24 [2] 43 23 [2] 5f 0c }

  condition:
    any of them
}