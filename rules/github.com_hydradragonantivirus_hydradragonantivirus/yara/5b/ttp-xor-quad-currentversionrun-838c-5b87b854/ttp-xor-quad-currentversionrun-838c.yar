rule TTP_XOR_QUAD_CurrentVersionRun_838c {
  strings:
    $key_838c = { d0 e3 [2] f4 ed [2] df c1 [2] f1 e3 [2] e5 f8 [2] ea e2 [2] f4 ff [2] f6 fe [2] ed f8 [2] f1 ff [2] ed d0 }

  condition:
    any of them
}