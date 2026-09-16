rule TTP_XOR_QUAD_CurrentVersionRun_ddce {
  strings:
    $key_ddce = { 8e a1 [2] aa af [2] 81 83 [2] af a1 [2] bb ba [2] b4 a0 [2] aa bd [2] a8 bc [2] b3 ba [2] af bd [2] b3 92 }

  condition:
    any of them
}