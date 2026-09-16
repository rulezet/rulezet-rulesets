rule TTP_XOR_QUAD_CurrentVersionRun_57cf {
  strings:
    $key_57cf = { 04 a0 [2] 20 ae [2] 0b 82 [2] 25 a0 [2] 31 bb [2] 3e a1 [2] 20 bc [2] 22 bd [2] 39 bb [2] 25 bc [2] 39 93 }

  condition:
    any of them
}