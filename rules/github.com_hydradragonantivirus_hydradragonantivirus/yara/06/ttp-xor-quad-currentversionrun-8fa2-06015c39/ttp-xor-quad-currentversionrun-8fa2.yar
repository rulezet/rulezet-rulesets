rule TTP_XOR_QUAD_CurrentVersionRun_8fa2 {
  strings:
    $key_8fa2 = { dc cd [2] f8 c3 [2] d3 ef [2] fd cd [2] e9 d6 [2] e6 cc [2] f8 d1 [2] fa d0 [2] e1 d6 [2] fd d1 [2] e1 fe }

  condition:
    any of them
}