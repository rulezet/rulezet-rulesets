rule TTP_XOR_QUAD_CurrentVersionRun_b3a2 {
  strings:
    $key_b3a2 = { e0 cd [2] c4 c3 [2] ef ef [2] c1 cd [2] d5 d6 [2] da cc [2] c4 d1 [2] c6 d0 [2] dd d6 [2] c1 d1 [2] dd fe }

  condition:
    any of them
}