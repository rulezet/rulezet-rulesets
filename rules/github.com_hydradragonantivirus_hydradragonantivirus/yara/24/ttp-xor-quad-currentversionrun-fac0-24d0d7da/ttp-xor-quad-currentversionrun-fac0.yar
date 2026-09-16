rule TTP_XOR_QUAD_CurrentVersionRun_fac0 {
  strings:
    $key_fac0 = { a9 af [2] 8d a1 [2] a6 8d [2] 88 af [2] 9c b4 [2] 93 ae [2] 8d b3 [2] 8f b2 [2] 94 b4 [2] 88 b3 [2] 94 9c }

  condition:
    any of them
}