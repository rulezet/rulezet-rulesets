rule TTP_XOR_QUAD_CurrentVersionRun_fec0 {
  strings:
    $key_fec0 = { ad af [2] 89 a1 [2] a2 8d [2] 8c af [2] 98 b4 [2] 97 ae [2] 89 b3 [2] 8b b2 [2] 90 b4 [2] 8c b3 [2] 90 9c }

  condition:
    any of them
}