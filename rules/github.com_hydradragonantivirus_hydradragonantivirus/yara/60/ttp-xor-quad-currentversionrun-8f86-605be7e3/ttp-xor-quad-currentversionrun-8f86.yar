rule TTP_XOR_QUAD_CurrentVersionRun_8f86 {
  strings:
    $key_8f86 = { dc e9 [2] f8 e7 [2] d3 cb [2] fd e9 [2] e9 f2 [2] e6 e8 [2] f8 f5 [2] fa f4 [2] e1 f2 [2] fd f5 [2] e1 da }

  condition:
    any of them
}