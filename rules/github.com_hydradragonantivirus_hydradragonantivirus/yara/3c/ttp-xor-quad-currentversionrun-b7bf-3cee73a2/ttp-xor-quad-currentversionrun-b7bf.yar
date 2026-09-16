rule TTP_XOR_QUAD_CurrentVersionRun_b7bf {
  strings:
    $key_b7bf = { e4 d0 [2] c0 de [2] eb f2 [2] c5 d0 [2] d1 cb [2] de d1 [2] c0 cc [2] c2 cd [2] d9 cb [2] c5 cc [2] d9 e3 }

  condition:
    any of them
}