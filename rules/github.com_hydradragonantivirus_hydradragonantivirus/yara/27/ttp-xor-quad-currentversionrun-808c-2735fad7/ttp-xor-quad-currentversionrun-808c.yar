rule TTP_XOR_QUAD_CurrentVersionRun_808c {
  strings:
    $key_808c = { d3 e3 [2] f7 ed [2] dc c1 [2] f2 e3 [2] e6 f8 [2] e9 e2 [2] f7 ff [2] f5 fe [2] ee f8 [2] f2 ff [2] ee d0 }

  condition:
    any of them
}