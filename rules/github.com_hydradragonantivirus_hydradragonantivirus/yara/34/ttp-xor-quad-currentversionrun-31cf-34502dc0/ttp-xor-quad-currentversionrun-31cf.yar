rule TTP_XOR_QUAD_CurrentVersionRun_31cf {
  strings:
    $key_31cf = { 62 a0 [2] 46 ae [2] 6d 82 [2] 43 a0 [2] 57 bb [2] 58 a1 [2] 46 bc [2] 44 bd [2] 5f bb [2] 43 bc [2] 5f 93 }

  condition:
    any of them
}