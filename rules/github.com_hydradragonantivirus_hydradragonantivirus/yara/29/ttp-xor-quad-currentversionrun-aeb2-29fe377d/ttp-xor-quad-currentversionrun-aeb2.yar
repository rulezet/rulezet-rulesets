rule TTP_XOR_QUAD_CurrentVersionRun_aeb2 {
  strings:
    $key_aeb2 = { fd dd [2] d9 d3 [2] f2 ff [2] dc dd [2] c8 c6 [2] c7 dc [2] d9 c1 [2] db c0 [2] c0 c6 [2] dc c1 [2] c0 ee }

  condition:
    any of them
}