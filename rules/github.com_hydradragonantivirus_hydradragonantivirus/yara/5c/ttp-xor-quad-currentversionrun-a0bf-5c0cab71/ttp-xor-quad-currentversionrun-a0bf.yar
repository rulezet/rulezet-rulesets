rule TTP_XOR_QUAD_CurrentVersionRun_a0bf {
  strings:
    $key_a0bf = { f3 d0 [2] d7 de [2] fc f2 [2] d2 d0 [2] c6 cb [2] c9 d1 [2] d7 cc [2] d5 cd [2] ce cb [2] d2 cc [2] ce e3 }

  condition:
    any of them
}