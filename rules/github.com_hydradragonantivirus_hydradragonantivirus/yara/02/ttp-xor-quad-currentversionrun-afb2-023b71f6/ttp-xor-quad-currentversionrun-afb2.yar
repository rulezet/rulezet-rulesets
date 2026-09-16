rule TTP_XOR_QUAD_CurrentVersionRun_afb2 {
  strings:
    $key_afb2 = { fc dd [2] d8 d3 [2] f3 ff [2] dd dd [2] c9 c6 [2] c6 dc [2] d8 c1 [2] da c0 [2] c1 c6 [2] dd c1 [2] c1 ee }

  condition:
    any of them
}