rule TTP_XOR_QUAD_CurrentVersionRun_b0b3 {
  strings:
    $key_b0b3 = { e3 dc [2] c7 d2 [2] ec fe [2] c2 dc [2] d6 c7 [2] d9 dd [2] c7 c0 [2] c5 c1 [2] de c7 [2] c2 c0 [2] de ef }

  condition:
    any of them
}