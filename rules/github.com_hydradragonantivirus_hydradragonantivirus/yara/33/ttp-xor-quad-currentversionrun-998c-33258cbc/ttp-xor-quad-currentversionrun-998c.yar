rule TTP_XOR_QUAD_CurrentVersionRun_998c {
  strings:
    $key_998c = { ca e3 [2] ee ed [2] c5 c1 [2] eb e3 [2] ff f8 [2] f0 e2 [2] ee ff [2] ec fe [2] f7 f8 [2] eb ff [2] f7 d0 }

  condition:
    any of them
}