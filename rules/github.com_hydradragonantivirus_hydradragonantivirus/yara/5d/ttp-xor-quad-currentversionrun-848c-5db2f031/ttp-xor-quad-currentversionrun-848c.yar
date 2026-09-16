rule TTP_XOR_QUAD_CurrentVersionRun_848c {
  strings:
    $key_848c = { d7 e3 [2] f3 ed [2] d8 c1 [2] f6 e3 [2] e2 f8 [2] ed e2 [2] f3 ff [2] f1 fe [2] ea f8 [2] f6 ff [2] ea d0 }

  condition:
    any of them
}