rule TTP_XOR_QUAD_CurrentVersionRun_b1bf {
  strings:
    $key_b1bf = { e2 d0 [2] c6 de [2] ed f2 [2] c3 d0 [2] d7 cb [2] d8 d1 [2] c6 cc [2] c4 cd [2] df cb [2] c3 cc [2] df e3 }

  condition:
    any of them
}