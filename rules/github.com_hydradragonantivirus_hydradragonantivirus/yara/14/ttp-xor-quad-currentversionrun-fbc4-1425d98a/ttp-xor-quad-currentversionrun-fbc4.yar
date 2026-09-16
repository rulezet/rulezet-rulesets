rule TTP_XOR_QUAD_CurrentVersionRun_fbc4 {
  strings:
    $key_fbc4 = { a8 ab [2] 8c a5 [2] a7 89 [2] 89 ab [2] 9d b0 [2] 92 aa [2] 8c b7 [2] 8e b6 [2] 95 b0 [2] 89 b7 [2] 95 98 }

  condition:
    any of them
}