rule TTP_XOR_QUAD_CurrentVersionRun_0846 {
  strings:
    $key_0846 = { 5b 29 [2] 7f 27 [2] 54 0b [2] 7a 29 [2] 6e 32 [2] 61 28 [2] 7f 35 [2] 7d 34 [2] 66 32 [2] 7a 35 [2] 66 1a }

  condition:
    any of them
}