rule TTP_XOR_QUAD_CurrentVersionRun_aacc {
  strings:
    $key_aacc = { f9 a3 [2] dd ad [2] f6 81 [2] d8 a3 [2] cc b8 [2] c3 a2 [2] dd bf [2] df be [2] c4 b8 [2] d8 bf [2] c4 90 }

  condition:
    any of them
}