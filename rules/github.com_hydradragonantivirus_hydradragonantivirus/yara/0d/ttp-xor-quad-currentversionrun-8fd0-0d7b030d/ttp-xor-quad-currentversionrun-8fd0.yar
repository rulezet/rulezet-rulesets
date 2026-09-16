rule TTP_XOR_QUAD_CurrentVersionRun_8fd0 {
  strings:
    $key_8fd0 = { dc bf [2] f8 b1 [2] d3 9d [2] fd bf [2] e9 a4 [2] e6 be [2] f8 a3 [2] fa a2 [2] e1 a4 [2] fd a3 [2] e1 8c }

  condition:
    any of them
}