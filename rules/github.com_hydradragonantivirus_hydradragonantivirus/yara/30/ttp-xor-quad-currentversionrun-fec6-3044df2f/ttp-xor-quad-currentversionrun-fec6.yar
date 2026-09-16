rule TTP_XOR_QUAD_CurrentVersionRun_fec6 {
  strings:
    $key_fec6 = { ad a9 [2] 89 a7 [2] a2 8b [2] 8c a9 [2] 98 b2 [2] 97 a8 [2] 89 b5 [2] 8b b4 [2] 90 b2 [2] 8c b5 [2] 90 9a }

  condition:
    any of them
}