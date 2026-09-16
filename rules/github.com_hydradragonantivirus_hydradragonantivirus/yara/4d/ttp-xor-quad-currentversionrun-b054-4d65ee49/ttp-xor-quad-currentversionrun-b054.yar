rule TTP_XOR_QUAD_CurrentVersionRun_b054 {
  strings:
    $key_b054 = { e3 3b [2] c7 35 [2] ec 19 [2] c2 3b [2] d6 20 [2] d9 3a [2] c7 27 [2] c5 26 [2] de 20 [2] c2 27 [2] de 08 }

  condition:
    any of them
}