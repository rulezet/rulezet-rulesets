rule TTP_XOR_QUAD_CurrentVersionRun_a993 {
  strings:
    $key_a993 = { fa fc [2] de f2 [2] f5 de [2] db fc [2] cf e7 [2] c0 fd [2] de e0 [2] dc e1 [2] c7 e7 [2] db e0 [2] c7 cf }

  condition:
    any of them
}