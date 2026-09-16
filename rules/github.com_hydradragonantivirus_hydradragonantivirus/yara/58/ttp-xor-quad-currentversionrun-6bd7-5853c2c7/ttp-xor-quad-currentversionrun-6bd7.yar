rule TTP_XOR_QUAD_CurrentVersionRun_6bd7 {
  strings:
    $key_6bd7 = { 38 b8 [2] 1c b6 [2] 37 9a [2] 19 b8 [2] 0d a3 [2] 02 b9 [2] 1c a4 [2] 1e a5 [2] 05 a3 [2] 19 a4 [2] 05 8b }

  condition:
    any of them
}