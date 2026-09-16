rule TTP_XOR_QUAD_CurrentVersionRun_d8a0 {
  strings:
    $key_d8a0 = { 8b cf [2] af c1 [2] 84 ed [2] aa cf [2] be d4 [2] b1 ce [2] af d3 [2] ad d2 [2] b6 d4 [2] aa d3 [2] b6 fc }

  condition:
    any of them
}