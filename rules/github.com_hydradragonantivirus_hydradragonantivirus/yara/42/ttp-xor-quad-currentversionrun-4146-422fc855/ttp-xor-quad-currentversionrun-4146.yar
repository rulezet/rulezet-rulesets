rule TTP_XOR_QUAD_CurrentVersionRun_4146 {
  strings:
    $key_4146 = { 12 29 [2] 36 27 [2] 1d 0b [2] 33 29 [2] 27 32 [2] 28 28 [2] 36 35 [2] 34 34 [2] 2f 32 [2] 33 35 [2] 2f 1a }

  condition:
    any of them
}