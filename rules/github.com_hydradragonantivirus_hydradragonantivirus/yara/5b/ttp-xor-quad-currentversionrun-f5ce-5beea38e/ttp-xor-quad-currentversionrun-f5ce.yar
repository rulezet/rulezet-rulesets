rule TTP_XOR_QUAD_CurrentVersionRun_f5ce {
  strings:
    $key_f5ce = { a6 a1 [2] 82 af [2] a9 83 [2] 87 a1 [2] 93 ba [2] 9c a0 [2] 82 bd [2] 80 bc [2] 9b ba [2] 87 bd [2] 9b 92 }

  condition:
    any of them
}