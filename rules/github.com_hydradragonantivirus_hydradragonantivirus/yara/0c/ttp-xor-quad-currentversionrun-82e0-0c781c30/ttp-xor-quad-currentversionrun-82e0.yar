rule TTP_XOR_QUAD_CurrentVersionRun_82e0 {
  strings:
    $key_82e0 = { d1 8f [2] f5 81 [2] de ad [2] f0 8f [2] e4 94 [2] eb 8e [2] f5 93 [2] f7 92 [2] ec 94 [2] f0 93 [2] ec bc }

  condition:
    any of them
}