rule TTP_XOR_QUAD_CurrentVersionRun_8fd1 {
  strings:
    $key_8fd1 = { dc be [2] f8 b0 [2] d3 9c [2] fd be [2] e9 a5 [2] e6 bf [2] f8 a2 [2] fa a3 [2] e1 a5 [2] fd a2 [2] e1 8d }

  condition:
    any of them
}