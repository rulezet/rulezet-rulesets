rule TTP_XOR_QUAD_CurrentVersionRun_8f81 {
  strings:
    $key_8f81 = { dc ee [2] f8 e0 [2] d3 cc [2] fd ee [2] e9 f5 [2] e6 ef [2] f8 f2 [2] fa f3 [2] e1 f5 [2] fd f2 [2] e1 dd }

  condition:
    any of them
}