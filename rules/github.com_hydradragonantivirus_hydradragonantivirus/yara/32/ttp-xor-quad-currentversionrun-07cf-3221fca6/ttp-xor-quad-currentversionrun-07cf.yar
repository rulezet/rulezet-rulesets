rule TTP_XOR_QUAD_CurrentVersionRun_07cf {
  strings:
    $key_07cf = { 54 a0 [2] 70 ae [2] 5b 82 [2] 75 a0 [2] 61 bb [2] 6e a1 [2] 70 bc [2] 72 bd [2] 69 bb [2] 75 bc [2] 69 93 }

  condition:
    any of them
}