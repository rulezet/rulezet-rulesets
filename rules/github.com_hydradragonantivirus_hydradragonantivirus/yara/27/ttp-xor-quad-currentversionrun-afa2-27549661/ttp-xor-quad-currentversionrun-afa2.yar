rule TTP_XOR_QUAD_CurrentVersionRun_afa2 {
  strings:
    $key_afa2 = { fc cd [2] d8 c3 [2] f3 ef [2] dd cd [2] c9 d6 [2] c6 cc [2] d8 d1 [2] da d0 [2] c1 d6 [2] dd d1 [2] c1 fe }

  condition:
    any of them
}