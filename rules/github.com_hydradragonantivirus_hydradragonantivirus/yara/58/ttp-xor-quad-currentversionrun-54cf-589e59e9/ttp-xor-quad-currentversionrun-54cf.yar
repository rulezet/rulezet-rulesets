rule TTP_XOR_QUAD_CurrentVersionRun_54cf {
  strings:
    $key_54cf = { 07 a0 [2] 23 ae [2] 08 82 [2] 26 a0 [2] 32 bb [2] 3d a1 [2] 23 bc [2] 21 bd [2] 3a bb [2] 26 bc [2] 3a 93 }

  condition:
    any of them
}