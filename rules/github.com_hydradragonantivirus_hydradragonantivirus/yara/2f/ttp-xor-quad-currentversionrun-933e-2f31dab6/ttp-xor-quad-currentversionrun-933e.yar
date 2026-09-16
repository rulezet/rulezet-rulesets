rule TTP_XOR_QUAD_CurrentVersionRun_933e {
  strings:
    $key_933e = { c0 51 [2] e4 5f [2] cf 73 [2] e1 51 [2] f5 4a [2] fa 50 [2] e4 4d [2] e6 4c [2] fd 4a [2] e1 4d [2] fd 62 }

  condition:
    any of them
}