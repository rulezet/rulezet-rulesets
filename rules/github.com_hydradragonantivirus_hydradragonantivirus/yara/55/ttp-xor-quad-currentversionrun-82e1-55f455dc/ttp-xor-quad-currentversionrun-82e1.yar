rule TTP_XOR_QUAD_CurrentVersionRun_82e1 {
  strings:
    $key_82e1 = { d1 8e [2] f5 80 [2] de ac [2] f0 8e [2] e4 95 [2] eb 8f [2] f5 92 [2] f7 93 [2] ec 95 [2] f0 92 [2] ec bd }

  condition:
    any of them
}