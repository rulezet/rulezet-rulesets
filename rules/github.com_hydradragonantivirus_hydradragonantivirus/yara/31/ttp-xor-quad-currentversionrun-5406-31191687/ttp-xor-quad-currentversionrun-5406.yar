rule TTP_XOR_QUAD_CurrentVersionRun_5406 {
  strings:
    $key_5406 = { 07 69 [2] 23 67 [2] 08 4b [2] 26 69 [2] 32 72 [2] 3d 68 [2] 23 75 [2] 21 74 [2] 3a 72 [2] 26 75 [2] 3a 5a }

  condition:
    any of them
}