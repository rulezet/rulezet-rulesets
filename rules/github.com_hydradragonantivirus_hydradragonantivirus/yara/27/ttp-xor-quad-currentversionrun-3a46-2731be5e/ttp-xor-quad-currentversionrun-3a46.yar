rule TTP_XOR_QUAD_CurrentVersionRun_3a46 {
  strings:
    $key_3a46 = { 69 29 [2] 4d 27 [2] 66 0b [2] 48 29 [2] 5c 32 [2] 53 28 [2] 4d 35 [2] 4f 34 [2] 54 32 [2] 48 35 [2] 54 1a }

  condition:
    any of them
}