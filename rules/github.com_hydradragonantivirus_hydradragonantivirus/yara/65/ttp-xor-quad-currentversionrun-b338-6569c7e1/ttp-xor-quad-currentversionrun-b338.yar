rule TTP_XOR_QUAD_CurrentVersionRun_b338 {
  strings:
    $key_b338 = { e0 57 [2] c4 59 [2] ef 75 [2] c1 57 [2] d5 4c [2] da 56 [2] c4 4b [2] c6 4a [2] dd 4c [2] c1 4b [2] dd 64 }

  condition:
    any of them
}