rule TTP_XOR_QUAD_CurrentVersionRun_a996 {
  strings:
    $key_a996 = { fa f9 [2] de f7 [2] f5 db [2] db f9 [2] cf e2 [2] c0 f8 [2] de e5 [2] dc e4 [2] c7 e2 [2] db e5 [2] c7 ca }

  condition:
    any of them
}