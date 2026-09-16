rule TTP_XOR_QUAD_CurrentVersionRun_fbc6 {
  strings:
    $key_fbc6 = { a8 a9 [2] 8c a7 [2] a7 8b [2] 89 a9 [2] 9d b2 [2] 92 a8 [2] 8c b5 [2] 8e b4 [2] 95 b2 [2] 89 b5 [2] 95 9a }

  condition:
    any of them
}