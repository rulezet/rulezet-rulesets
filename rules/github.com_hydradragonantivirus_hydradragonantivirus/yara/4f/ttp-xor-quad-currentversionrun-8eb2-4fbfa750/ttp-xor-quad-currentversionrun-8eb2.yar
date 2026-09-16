rule TTP_XOR_QUAD_CurrentVersionRun_8eb2 {
  strings:
    $key_8eb2 = { dd dd [2] f9 d3 [2] d2 ff [2] fc dd [2] e8 c6 [2] e7 dc [2] f9 c1 [2] fb c0 [2] e0 c6 [2] fc c1 [2] e0 ee }

  condition:
    any of them
}