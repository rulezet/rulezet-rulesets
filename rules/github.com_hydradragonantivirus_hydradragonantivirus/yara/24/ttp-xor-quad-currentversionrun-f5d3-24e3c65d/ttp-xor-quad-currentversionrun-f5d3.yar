rule TTP_XOR_QUAD_CurrentVersionRun_f5d3 {
  strings:
    $key_f5d3 = { a6 bc [2] 82 b2 [2] a9 9e [2] 87 bc [2] 93 a7 [2] 9c bd [2] 82 a0 [2] 80 a1 [2] 9b a7 [2] 87 a0 [2] 9b 8f }

  condition:
    any of them
}