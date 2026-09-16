rule TTP_XOR_QUAD_CurrentVersionRun_f0cf {
  strings:
    $key_f0cf = { a3 a0 [2] 87 ae [2] ac 82 [2] 82 a0 [2] 96 bb [2] 99 a1 [2] 87 bc [2] 85 bd [2] 9e bb [2] 82 bc [2] 9e 93 }

  condition:
    any of them
}