rule TTP_XOR_QUAD_CurrentVersionRun_96e1 {
  strings:
    $key_96e1 = { c5 8e [2] e1 80 [2] ca ac [2] e4 8e [2] f0 95 [2] ff 8f [2] e1 92 [2] e3 93 [2] f8 95 [2] e4 92 [2] f8 bd }

  condition:
    any of them
}