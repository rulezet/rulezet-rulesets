rule TTP_XOR_QUAD_CurrentVersionRun_b3e5 {
  strings:
    $key_b3e5 = { e0 8a [2] c4 84 [2] ef a8 [2] c1 8a [2] d5 91 [2] da 8b [2] c4 96 [2] c6 97 [2] dd 91 [2] c1 96 [2] dd b9 }

  condition:
    any of them
}