rule TTP_XOR_QUAD_CurrentVersionRun_8590 {
  strings:
    $key_8590 = { d6 ff [2] f2 f1 [2] d9 dd [2] f7 ff [2] e3 e4 [2] ec fe [2] f2 e3 [2] f0 e2 [2] eb e4 [2] f7 e3 [2] eb cc }

  condition:
    any of them
}