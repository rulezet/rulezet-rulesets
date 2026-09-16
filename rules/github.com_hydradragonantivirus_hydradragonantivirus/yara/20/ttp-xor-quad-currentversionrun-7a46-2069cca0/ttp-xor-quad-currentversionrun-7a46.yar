rule TTP_XOR_QUAD_CurrentVersionRun_7a46 {
  strings:
    $key_7a46 = { 29 29 [2] 0d 27 [2] 26 0b [2] 08 29 [2] 1c 32 [2] 13 28 [2] 0d 35 [2] 0f 34 [2] 14 32 [2] 08 35 [2] 14 1a }

  condition:
    any of them
}