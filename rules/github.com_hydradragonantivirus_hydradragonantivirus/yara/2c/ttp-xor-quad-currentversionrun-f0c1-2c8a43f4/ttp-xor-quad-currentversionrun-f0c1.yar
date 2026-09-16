rule TTP_XOR_QUAD_CurrentVersionRun_f0c1 {
  strings:
    $key_f0c1 = { a3 ae [2] 87 a0 [2] ac 8c [2] 82 ae [2] 96 b5 [2] 99 af [2] 87 b2 [2] 85 b3 [2] 9e b5 [2] 82 b2 [2] 9e 9d }

  condition:
    any of them
}