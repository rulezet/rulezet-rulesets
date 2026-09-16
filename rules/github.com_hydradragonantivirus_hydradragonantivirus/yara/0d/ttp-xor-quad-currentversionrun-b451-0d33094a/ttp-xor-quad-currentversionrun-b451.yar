rule TTP_XOR_QUAD_CurrentVersionRun_b451 {
  strings:
    $key_b451 = { e7 3e [2] c3 30 [2] e8 1c [2] c6 3e [2] d2 25 [2] dd 3f [2] c3 22 [2] c1 23 [2] da 25 [2] c6 22 [2] da 0d }

  condition:
    any of them
}