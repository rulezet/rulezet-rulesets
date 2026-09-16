rule TTP_XOR_QUAD_CurrentVersionRun_12cf {
  strings:
    $key_12cf = { 41 a0 [2] 65 ae [2] 4e 82 [2] 60 a0 [2] 74 bb [2] 7b a1 [2] 65 bc [2] 67 bd [2] 7c bb [2] 60 bc [2] 7c 93 }

  condition:
    any of them
}