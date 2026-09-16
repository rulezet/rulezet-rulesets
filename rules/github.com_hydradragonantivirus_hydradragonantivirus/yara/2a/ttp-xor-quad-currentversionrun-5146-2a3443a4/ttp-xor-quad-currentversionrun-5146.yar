rule TTP_XOR_QUAD_CurrentVersionRun_5146 {
  strings:
    $key_5146 = { 02 29 [2] 26 27 [2] 0d 0b [2] 23 29 [2] 37 32 [2] 38 28 [2] 26 35 [2] 24 34 [2] 3f 32 [2] 23 35 [2] 3f 1a }

  condition:
    any of them
}