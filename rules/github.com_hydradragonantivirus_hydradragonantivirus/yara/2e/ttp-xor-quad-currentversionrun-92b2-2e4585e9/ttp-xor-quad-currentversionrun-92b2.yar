rule TTP_XOR_QUAD_CurrentVersionRun_92b2 {
  strings:
    $key_92b2 = { c1 dd [2] e5 d3 [2] ce ff [2] e0 dd [2] f4 c6 [2] fb dc [2] e5 c1 [2] e7 c0 [2] fc c6 [2] e0 c1 [2] fc ee }

  condition:
    any of them
}