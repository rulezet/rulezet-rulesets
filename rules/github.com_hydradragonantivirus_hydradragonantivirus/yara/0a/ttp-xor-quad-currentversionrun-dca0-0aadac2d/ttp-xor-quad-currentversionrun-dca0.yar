rule TTP_XOR_QUAD_CurrentVersionRun_dca0 {
  strings:
    $key_dca0 = { 8f cf [2] ab c1 [2] 80 ed [2] ae cf [2] ba d4 [2] b5 ce [2] ab d3 [2] a9 d2 [2] b2 d4 [2] ae d3 [2] b2 fc }

  condition:
    any of them
}