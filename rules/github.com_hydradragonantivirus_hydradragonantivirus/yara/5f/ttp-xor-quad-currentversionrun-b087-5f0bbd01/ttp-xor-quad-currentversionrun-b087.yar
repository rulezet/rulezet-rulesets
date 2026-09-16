rule TTP_XOR_QUAD_CurrentVersionRun_b087 {
  strings:
    $key_b087 = { e3 e8 [2] c7 e6 [2] ec ca [2] c2 e8 [2] d6 f3 [2] d9 e9 [2] c7 f4 [2] c5 f5 [2] de f3 [2] c2 f4 [2] de db }

  condition:
    any of them
}