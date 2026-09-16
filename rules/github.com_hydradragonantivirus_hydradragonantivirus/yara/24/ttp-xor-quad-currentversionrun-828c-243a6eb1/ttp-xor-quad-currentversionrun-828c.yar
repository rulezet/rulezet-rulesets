rule TTP_XOR_QUAD_CurrentVersionRun_828c {
  strings:
    $key_828c = { d1 e3 [2] f5 ed [2] de c1 [2] f0 e3 [2] e4 f8 [2] eb e2 [2] f5 ff [2] f7 fe [2] ec f8 [2] f0 ff [2] ec d0 }

  condition:
    any of them
}