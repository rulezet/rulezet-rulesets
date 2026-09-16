rule TTP_XOR_QUAD_CurrentVersionRun_8880 {
  strings:
    $key_8880 = { db ef [2] ff e1 [2] d4 cd [2] fa ef [2] ee f4 [2] e1 ee [2] ff f3 [2] fd f2 [2] e6 f4 [2] fa f3 [2] e6 dc }

  condition:
    any of them
}