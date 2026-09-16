rule TTP_XOR_QUAD_CurrentVersionRun_af9e {
  strings:
    $key_af9e = { fc f1 [2] d8 ff [2] f3 d3 [2] dd f1 [2] c9 ea [2] c6 f0 [2] d8 ed [2] da ec [2] c1 ea [2] dd ed [2] c1 c2 }

  condition:
    any of them
}