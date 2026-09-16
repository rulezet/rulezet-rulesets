rule TTP_XOR_QUAD_CurrentVersionRun_9e90 {
  strings:
    $key_9e90 = { cd ff [2] e9 f1 [2] c2 dd [2] ec ff [2] f8 e4 [2] f7 fe [2] e9 e3 [2] eb e2 [2] f0 e4 [2] ec e3 [2] f0 cc }

  condition:
    any of them
}