rule TTP_XOR_QUAD_CurrentVersionRun_e2cf {
  strings:
    $key_e2cf = { b1 a0 [2] 95 ae [2] be 82 [2] 90 a0 [2] 84 bb [2] 8b a1 [2] 95 bc [2] 97 bd [2] 8c bb [2] 90 bc [2] 8c 93 }

  condition:
    any of them
}