rule TTP_XOR_QUAD_CurrentVersionRun_8881 {
  strings:
    $key_8881 = { db ee [2] ff e0 [2] d4 cc [2] fa ee [2] ee f5 [2] e1 ef [2] ff f2 [2] fd f3 [2] e6 f5 [2] fa f2 [2] e6 dd }

  condition:
    any of them
}