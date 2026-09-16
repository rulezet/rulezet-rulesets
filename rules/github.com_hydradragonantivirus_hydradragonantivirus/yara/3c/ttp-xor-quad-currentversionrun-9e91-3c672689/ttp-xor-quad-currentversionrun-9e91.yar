rule TTP_XOR_QUAD_CurrentVersionRun_9e91 {
  strings:
    $key_9e91 = { cd fe [2] e9 f0 [2] c2 dc [2] ec fe [2] f8 e5 [2] f7 ff [2] e9 e2 [2] eb e3 [2] f0 e5 [2] ec e2 [2] f0 cd }

  condition:
    any of them
}