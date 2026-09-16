rule TTP_XOR_QUAD_CurrentVersionRun_d8bd {
  strings:
    $key_d8bd = { 8b d2 [2] af dc [2] 84 f0 [2] aa d2 [2] be c9 [2] b1 d3 [2] af ce [2] ad cf [2] b6 c9 [2] aa ce [2] b6 e1 }

  condition:
    any of them
}