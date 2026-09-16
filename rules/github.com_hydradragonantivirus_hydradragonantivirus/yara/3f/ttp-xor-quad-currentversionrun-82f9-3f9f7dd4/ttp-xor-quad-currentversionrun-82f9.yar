rule TTP_XOR_QUAD_CurrentVersionRun_82f9 {
  strings:
    $key_82f9 = { d1 96 [2] f5 98 [2] de b4 [2] f0 96 [2] e4 8d [2] eb 97 [2] f5 8a [2] f7 8b [2] ec 8d [2] f0 8a [2] ec a5 }

  condition:
    any of them
}