rule TTP_XOR_QUAD_CurrentVersionRun_e6cf {
  strings:
    $key_e6cf = { b5 a0 [2] 91 ae [2] ba 82 [2] 94 a0 [2] 80 bb [2] 8f a1 [2] 91 bc [2] 93 bd [2] 88 bb [2] 94 bc [2] 88 93 }

  condition:
    any of them
}