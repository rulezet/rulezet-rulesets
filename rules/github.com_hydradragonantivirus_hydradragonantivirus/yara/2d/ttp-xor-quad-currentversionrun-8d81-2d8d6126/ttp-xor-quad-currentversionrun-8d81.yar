rule TTP_XOR_QUAD_CurrentVersionRun_8d81 {
  strings:
    $key_8d81 = { de ee [2] fa e0 [2] d1 cc [2] ff ee [2] eb f5 [2] e4 ef [2] fa f2 [2] f8 f3 [2] e3 f5 [2] ff f2 [2] e3 dd }

  condition:
    any of them
}