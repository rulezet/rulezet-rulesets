rule TTP_XOR_QUAD_CurrentVersionRun_d9a0 {
  strings:
    $key_d9a0 = { 8a cf [2] ae c1 [2] 85 ed [2] ab cf [2] bf d4 [2] b0 ce [2] ae d3 [2] ac d2 [2] b7 d4 [2] ab d3 [2] b7 fc }

  condition:
    any of them
}