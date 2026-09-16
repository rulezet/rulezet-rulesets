rule TTP_XOR_QUAD_CurrentVersionRun_828d {
  strings:
    $key_828d = { d1 e2 [2] f5 ec [2] de c0 [2] f0 e2 [2] e4 f9 [2] eb e3 [2] f5 fe [2] f7 ff [2] ec f9 [2] f0 fe [2] ec d1 }

  condition:
    any of them
}