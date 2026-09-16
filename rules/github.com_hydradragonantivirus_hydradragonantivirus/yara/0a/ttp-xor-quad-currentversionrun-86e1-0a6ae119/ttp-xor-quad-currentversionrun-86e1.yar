rule TTP_XOR_QUAD_CurrentVersionRun_86e1 {
  strings:
    $key_86e1 = { d5 8e [2] f1 80 [2] da ac [2] f4 8e [2] e0 95 [2] ef 8f [2] f1 92 [2] f3 93 [2] e8 95 [2] f4 92 [2] e8 bd }

  condition:
    any of them
}