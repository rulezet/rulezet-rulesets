rule TTP_XOR_QUAD_CurrentVersionRun_82f7 {
  strings:
    $key_82f7 = { d1 98 [2] f5 96 [2] de ba [2] f0 98 [2] e4 83 [2] eb 99 [2] f5 84 [2] f7 85 [2] ec 83 [2] f0 84 [2] ec ab }

  condition:
    any of them
}