rule TTP_XOR_QUAD_CurrentVersionRun_ac9f {
  strings:
    $key_ac9f = { ff f0 [2] db fe [2] f0 d2 [2] de f0 [2] ca eb [2] c5 f1 [2] db ec [2] d9 ed [2] c2 eb [2] de ec [2] c2 c3 }

  condition:
    any of them
}