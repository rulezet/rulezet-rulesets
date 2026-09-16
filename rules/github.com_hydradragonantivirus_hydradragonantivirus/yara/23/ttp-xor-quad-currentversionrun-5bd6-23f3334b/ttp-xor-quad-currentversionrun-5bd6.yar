rule TTP_XOR_QUAD_CurrentVersionRun_5bd6 {
  strings:
    $key_5bd6 = { 08 b9 [2] 2c b7 [2] 07 9b [2] 29 b9 [2] 3d a2 [2] 32 b8 [2] 2c a5 [2] 2e a4 [2] 35 a2 [2] 29 a5 [2] 35 8a }

  condition:
    any of them
}