rule TTP_XOR_QUAD_CurrentVersionRun_f2cf {
  strings:
    $key_f2cf = { a1 a0 [2] 85 ae [2] ae 82 [2] 80 a0 [2] 94 bb [2] 9b a1 [2] 85 bc [2] 87 bd [2] 9c bb [2] 80 bc [2] 9c 93 }

  condition:
    any of them
}