rule TTP_XOR_QUAD_CurrentVersionRun_ac8e {
  strings:
    $key_ac8e = { ff e1 [2] db ef [2] f0 c3 [2] de e1 [2] ca fa [2] c5 e0 [2] db fd [2] d9 fc [2] c2 fa [2] de fd [2] c2 d2 }

  condition:
    any of them
}