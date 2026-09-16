rule TTP_XOR_QUAD_CurrentVersionRun_6ed6 {
  strings:
    $key_6ed6 = { 3d b9 [2] 19 b7 [2] 32 9b [2] 1c b9 [2] 08 a2 [2] 07 b8 [2] 19 a5 [2] 1b a4 [2] 00 a2 [2] 1c a5 [2] 00 8a }

  condition:
    any of them
}