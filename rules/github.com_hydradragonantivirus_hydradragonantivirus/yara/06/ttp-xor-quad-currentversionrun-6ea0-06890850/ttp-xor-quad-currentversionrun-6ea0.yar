rule TTP_XOR_QUAD_CurrentVersionRun_6ea0 {
  strings:
    $key_6ea0 = { 3d cf [2] 19 c1 [2] 32 ed [2] 1c cf [2] 08 d4 [2] 07 ce [2] 19 d3 [2] 1b d2 [2] 00 d4 [2] 1c d3 [2] 00 fc }

  condition:
    any of them
}