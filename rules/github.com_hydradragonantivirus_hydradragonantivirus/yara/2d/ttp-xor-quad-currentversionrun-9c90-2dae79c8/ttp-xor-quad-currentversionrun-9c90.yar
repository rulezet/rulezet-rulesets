rule TTP_XOR_QUAD_CurrentVersionRun_9c90 {
  strings:
    $key_9c90 = { cf ff [2] eb f1 [2] c0 dd [2] ee ff [2] fa e4 [2] f5 fe [2] eb e3 [2] e9 e2 [2] f2 e4 [2] ee e3 [2] f2 cc }

  condition:
    any of them
}