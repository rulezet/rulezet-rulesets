rule TTP_XOR_QUAD_CurrentVersionRun_6a46 {
  strings:
    $key_6a46 = { 39 29 [2] 1d 27 [2] 36 0b [2] 18 29 [2] 0c 32 [2] 03 28 [2] 1d 35 [2] 1f 34 [2] 04 32 [2] 18 35 [2] 04 1a }

  condition:
    any of them
}