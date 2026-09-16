rule TTP_XOR_QUAD_CurrentVersionRun_93a2 {
  strings:
    $key_93a2 = { c0 cd [2] e4 c3 [2] cf ef [2] e1 cd [2] f5 d6 [2] fa cc [2] e4 d1 [2] e6 d0 [2] fd d6 [2] e1 d1 [2] fd fe }

  condition:
    any of them
}