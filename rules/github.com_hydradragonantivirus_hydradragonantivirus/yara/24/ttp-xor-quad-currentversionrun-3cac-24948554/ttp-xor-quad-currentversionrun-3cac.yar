rule TTP_XOR_QUAD_CurrentVersionRun_3cac {
  strings:
    $key_3cac = { 6f c3 [2] 4b cd [2] 60 e1 [2] 4e c3 [2] 5a d8 [2] 55 c2 [2] 4b df [2] 49 de [2] 52 d8 [2] 4e df [2] 52 f0 }

  condition:
    any of them
}