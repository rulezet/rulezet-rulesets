rule TTP_XOR_QUAD_CurrentVersionRun_2fa0 {
  strings:
    $key_2fa0 = { 7c cf [2] 58 c1 [2] 73 ed [2] 5d cf [2] 49 d4 [2] 46 ce [2] 58 d3 [2] 5a d2 [2] 41 d4 [2] 5d d3 [2] 41 fc }

  condition:
    any of them
}