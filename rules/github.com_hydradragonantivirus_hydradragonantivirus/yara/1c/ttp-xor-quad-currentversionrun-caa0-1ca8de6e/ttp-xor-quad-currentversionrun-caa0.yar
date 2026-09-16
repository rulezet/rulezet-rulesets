rule TTP_XOR_QUAD_CurrentVersionRun_caa0 {
  strings:
    $key_caa0 = { 99 cf [2] bd c1 [2] 96 ed [2] b8 cf [2] ac d4 [2] a3 ce [2] bd d3 [2] bf d2 [2] a4 d4 [2] b8 d3 [2] a4 fc }

  condition:
    any of them
}