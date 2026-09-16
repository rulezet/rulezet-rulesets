rule TTP_XOR_QUAD_CurrentVersionRun_cace {
  strings:
    $key_cace = { 99 a1 [2] bd af [2] 96 83 [2] b8 a1 [2] ac ba [2] a3 a0 [2] bd bd [2] bf bc [2] a4 ba [2] b8 bd [2] a4 92 }

  condition:
    any of them
}