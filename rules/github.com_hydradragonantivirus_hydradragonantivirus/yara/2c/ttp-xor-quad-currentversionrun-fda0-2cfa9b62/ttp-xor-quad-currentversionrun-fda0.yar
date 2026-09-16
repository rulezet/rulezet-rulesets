rule TTP_XOR_QUAD_CurrentVersionRun_fda0 {
  strings:
    $key_fda0 = { ae cf [2] 8a c1 [2] a1 ed [2] 8f cf [2] 9b d4 [2] 94 ce [2] 8a d3 [2] 88 d2 [2] 93 d4 [2] 8f d3 [2] 93 fc }

  condition:
    any of them
}