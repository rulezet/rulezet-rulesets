rule TTP_XOR_QUAD_CurrentVersionRun_b3e9 {
  strings:
    $key_b3e9 = { e0 86 [2] c4 88 [2] ef a4 [2] c1 86 [2] d5 9d [2] da 87 [2] c4 9a [2] c6 9b [2] dd 9d [2] c1 9a [2] dd b5 }

  condition:
    any of them
}