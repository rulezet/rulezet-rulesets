rule TTP_XOR_QUAD_CurrentVersionRun_92b1 {
  strings:
    $key_92b1 = { c1 de [2] e5 d0 [2] ce fc [2] e0 de [2] f4 c5 [2] fb df [2] e5 c2 [2] e7 c3 [2] fc c5 [2] e0 c2 [2] fc ed }

  condition:
    any of them
}