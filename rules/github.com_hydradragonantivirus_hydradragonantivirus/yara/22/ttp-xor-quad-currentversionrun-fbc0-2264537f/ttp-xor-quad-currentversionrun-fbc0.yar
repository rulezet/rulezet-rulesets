rule TTP_XOR_QUAD_CurrentVersionRun_fbc0 {
  strings:
    $key_fbc0 = { a8 af [2] 8c a1 [2] a7 8d [2] 89 af [2] 9d b4 [2] 92 ae [2] 8c b3 [2] 8e b2 [2] 95 b4 [2] 89 b3 [2] 95 9c }

  condition:
    any of them
}