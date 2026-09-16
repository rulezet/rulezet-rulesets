rule TTP_XOR_QUAD_CurrentVersionRun_fbc1 {
  strings:
    $key_fbc1 = { a8 ae [2] 8c a0 [2] a7 8c [2] 89 ae [2] 9d b5 [2] 92 af [2] 8c b2 [2] 8e b3 [2] 95 b5 [2] 89 b2 [2] 95 9d }

  condition:
    any of them
}