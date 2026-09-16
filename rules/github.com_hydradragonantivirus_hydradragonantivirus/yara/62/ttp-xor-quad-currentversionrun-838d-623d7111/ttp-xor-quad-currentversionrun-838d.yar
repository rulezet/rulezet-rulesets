rule TTP_XOR_QUAD_CurrentVersionRun_838d {
  strings:
    $key_838d = { d0 e2 [2] f4 ec [2] df c0 [2] f1 e2 [2] e5 f9 [2] ea e3 [2] f4 fe [2] f6 ff [2] ed f9 [2] f1 fe [2] ed d1 }

  condition:
    any of them
}