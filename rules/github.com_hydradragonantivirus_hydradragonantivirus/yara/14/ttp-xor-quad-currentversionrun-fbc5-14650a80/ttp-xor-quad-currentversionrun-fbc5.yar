rule TTP_XOR_QUAD_CurrentVersionRun_fbc5 {
  strings:
    $key_fbc5 = { a8 aa [2] 8c a4 [2] a7 88 [2] 89 aa [2] 9d b1 [2] 92 ab [2] 8c b6 [2] 8e b7 [2] 95 b1 [2] 89 b6 [2] 95 99 }

  condition:
    any of them
}