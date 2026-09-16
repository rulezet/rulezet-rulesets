rule TTP_XOR_QUAD_CurrentVersionRun_8bb3 {
  strings:
    $key_8bb3 = { d8 dc [2] fc d2 [2] d7 fe [2] f9 dc [2] ed c7 [2] e2 dd [2] fc c0 [2] fe c1 [2] e5 c7 [2] f9 c0 [2] e5 ef }

  condition:
    any of them
}