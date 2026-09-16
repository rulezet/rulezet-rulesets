rule TTP_XOR_QUAD_CurrentVersionRun_94a2 {
  strings:
    $key_94a2 = { c7 cd [2] e3 c3 [2] c8 ef [2] e6 cd [2] f2 d6 [2] fd cc [2] e3 d1 [2] e1 d0 [2] fa d6 [2] e6 d1 [2] fa fe }

  condition:
    any of them
}