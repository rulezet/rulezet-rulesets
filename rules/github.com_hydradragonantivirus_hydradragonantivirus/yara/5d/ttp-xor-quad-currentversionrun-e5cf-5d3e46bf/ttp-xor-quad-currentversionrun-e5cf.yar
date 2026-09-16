rule TTP_XOR_QUAD_CurrentVersionRun_e5cf {
  strings:
    $key_e5cf = { b6 a0 [2] 92 ae [2] b9 82 [2] 97 a0 [2] 83 bb [2] 8c a1 [2] 92 bc [2] 90 bd [2] 8b bb [2] 97 bc [2] 8b 93 }

  condition:
    any of them
}