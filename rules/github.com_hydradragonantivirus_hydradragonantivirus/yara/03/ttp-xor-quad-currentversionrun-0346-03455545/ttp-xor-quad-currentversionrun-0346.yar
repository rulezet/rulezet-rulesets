rule TTP_XOR_QUAD_CurrentVersionRun_0346 {
  strings:
    $key_0346 = { 50 29 [2] 74 27 [2] 5f 0b [2] 71 29 [2] 65 32 [2] 6a 28 [2] 74 35 [2] 76 34 [2] 6d 32 [2] 71 35 [2] 6d 1a }

  condition:
    any of them
}