rule TTP_XOR_QUAD_CurrentVersionRun_6bd6 {
  strings:
    $key_6bd6 = { 38 b9 [2] 1c b7 [2] 37 9b [2] 19 b9 [2] 0d a2 [2] 02 b8 [2] 1c a5 [2] 1e a4 [2] 05 a2 [2] 19 a5 [2] 05 8a }

  condition:
    any of them
}