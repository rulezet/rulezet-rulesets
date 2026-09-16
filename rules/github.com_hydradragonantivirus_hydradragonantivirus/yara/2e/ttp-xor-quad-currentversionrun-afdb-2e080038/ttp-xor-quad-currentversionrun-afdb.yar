rule TTP_XOR_QUAD_CurrentVersionRun_afdb {
  strings:
    $key_afdb = { fc b4 [2] d8 ba [2] f3 96 [2] dd b4 [2] c9 af [2] c6 b5 [2] d8 a8 [2] da a9 [2] c1 af [2] dd a8 [2] c1 87 }

  condition:
    any of them
}