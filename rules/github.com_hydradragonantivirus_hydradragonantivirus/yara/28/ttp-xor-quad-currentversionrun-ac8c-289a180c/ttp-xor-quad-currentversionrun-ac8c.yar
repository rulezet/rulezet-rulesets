rule TTP_XOR_QUAD_CurrentVersionRun_ac8c {
  strings:
    $key_ac8c = { ff e3 [2] db ed [2] f0 c1 [2] de e3 [2] ca f8 [2] c5 e2 [2] db ff [2] d9 fe [2] c2 f8 [2] de ff [2] c2 d0 }

  condition:
    any of them
}