rule TTP_XOR_QUAD_CurrentVersionRun_8f90 {
  strings:
    $key_8f90 = { dc ff [2] f8 f1 [2] d3 dd [2] fd ff [2] e9 e4 [2] e6 fe [2] f8 e3 [2] fa e2 [2] e1 e4 [2] fd e3 [2] e1 cc }

  condition:
    any of them
}