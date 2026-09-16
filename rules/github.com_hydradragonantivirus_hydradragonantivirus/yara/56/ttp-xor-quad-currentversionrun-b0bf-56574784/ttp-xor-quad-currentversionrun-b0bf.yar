rule TTP_XOR_QUAD_CurrentVersionRun_b0bf {
  strings:
    $key_b0bf = { e3 d0 [2] c7 de [2] ec f2 [2] c2 d0 [2] d6 cb [2] d9 d1 [2] c7 cc [2] c5 cd [2] de cb [2] c2 cc [2] de e3 }

  condition:
    any of them
}