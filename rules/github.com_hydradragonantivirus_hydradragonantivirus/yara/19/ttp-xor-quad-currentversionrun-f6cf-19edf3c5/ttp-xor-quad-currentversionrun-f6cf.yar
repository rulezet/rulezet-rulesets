rule TTP_XOR_QUAD_CurrentVersionRun_f6cf {
  strings:
    $key_f6cf = { a5 a0 [2] 81 ae [2] aa 82 [2] 84 a0 [2] 90 bb [2] 9f a1 [2] 81 bc [2] 83 bd [2] 98 bb [2] 84 bc [2] 98 93 }

  condition:
    any of them
}