rule TTP_XOR_QUAD_CurrentVersionRun_a0b2 {
  strings:
    $key_a0b2 = { f3 dd [2] d7 d3 [2] fc ff [2] d2 dd [2] c6 c6 [2] c9 dc [2] d7 c1 [2] d5 c0 [2] ce c6 [2] d2 c1 [2] ce ee }

  condition:
    any of them
}