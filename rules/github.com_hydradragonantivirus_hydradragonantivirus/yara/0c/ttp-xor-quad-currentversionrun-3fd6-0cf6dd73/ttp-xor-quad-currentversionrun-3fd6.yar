rule TTP_XOR_QUAD_CurrentVersionRun_3fd6 {
  strings:
    $key_3fd6 = { 6c b9 [2] 48 b7 [2] 63 9b [2] 4d b9 [2] 59 a2 [2] 56 b8 [2] 48 a5 [2] 4a a4 [2] 51 a2 [2] 4d a5 [2] 51 8a }

  condition:
    any of them
}