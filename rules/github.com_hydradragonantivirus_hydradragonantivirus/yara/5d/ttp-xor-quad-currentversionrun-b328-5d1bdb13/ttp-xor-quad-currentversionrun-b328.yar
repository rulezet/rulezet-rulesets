rule TTP_XOR_QUAD_CurrentVersionRun_b328 {
  strings:
    $key_b328 = { e0 47 [2] c4 49 [2] ef 65 [2] c1 47 [2] d5 5c [2] da 46 [2] c4 5b [2] c6 5a [2] dd 5c [2] c1 5b [2] dd 74 }

  condition:
    any of them
}