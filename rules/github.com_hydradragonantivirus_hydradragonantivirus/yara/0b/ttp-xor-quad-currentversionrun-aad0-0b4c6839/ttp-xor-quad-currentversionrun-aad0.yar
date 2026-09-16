rule TTP_XOR_QUAD_CurrentVersionRun_aad0 {
  strings:
    $key_aad0 = { f9 bf [2] dd b1 [2] f6 9d [2] d8 bf [2] cc a4 [2] c3 be [2] dd a3 [2] df a2 [2] c4 a4 [2] d8 a3 [2] c4 8c }

  condition:
    any of them
}