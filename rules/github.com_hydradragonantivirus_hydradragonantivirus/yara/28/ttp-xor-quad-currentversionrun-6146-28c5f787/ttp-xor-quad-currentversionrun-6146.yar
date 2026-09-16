rule TTP_XOR_QUAD_CurrentVersionRun_6146 {
  strings:
    $key_6146 = { 32 29 [2] 16 27 [2] 3d 0b [2] 13 29 [2] 07 32 [2] 08 28 [2] 16 35 [2] 14 34 [2] 0f 32 [2] 13 35 [2] 0f 1a }

  condition:
    any of them
}