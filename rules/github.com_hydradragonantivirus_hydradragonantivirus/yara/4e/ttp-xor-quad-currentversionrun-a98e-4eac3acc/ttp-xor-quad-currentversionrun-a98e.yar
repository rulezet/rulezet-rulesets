rule TTP_XOR_QUAD_CurrentVersionRun_a98e {
  strings:
    $key_a98e = { fa e1 [2] de ef [2] f5 c3 [2] db e1 [2] cf fa [2] c0 e0 [2] de fd [2] dc fc [2] c7 fa [2] db fd [2] c7 d2 }

  condition:
    any of them
}