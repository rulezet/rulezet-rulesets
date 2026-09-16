rule TTP_XOR_QUAD_CurrentVersionRun_eda0 {
  strings:
    $key_eda0 = { be cf [2] 9a c1 [2] b1 ed [2] 9f cf [2] 8b d4 [2] 84 ce [2] 9a d3 [2] 98 d2 [2] 83 d4 [2] 9f d3 [2] 83 fc }

  condition:
    any of them
}