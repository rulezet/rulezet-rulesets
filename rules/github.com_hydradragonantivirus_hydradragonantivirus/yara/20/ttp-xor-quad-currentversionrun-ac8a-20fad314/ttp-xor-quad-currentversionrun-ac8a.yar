rule TTP_XOR_QUAD_CurrentVersionRun_ac8a {
  strings:
    $key_ac8a = { ff e5 [2] db eb [2] f0 c7 [2] de e5 [2] ca fe [2] c5 e4 [2] db f9 [2] d9 f8 [2] c2 fe [2] de f9 [2] c2 d6 }

  condition:
    any of them
}