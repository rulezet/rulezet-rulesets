rule TTP_XOR_QUAD_CurrentVersionRun_aac0 {
  strings:
    $key_aac0 = { f9 af [2] dd a1 [2] f6 8d [2] d8 af [2] cc b4 [2] c3 ae [2] dd b3 [2] df b2 [2] c4 b4 [2] d8 b3 [2] c4 9c }

  condition:
    any of them
}