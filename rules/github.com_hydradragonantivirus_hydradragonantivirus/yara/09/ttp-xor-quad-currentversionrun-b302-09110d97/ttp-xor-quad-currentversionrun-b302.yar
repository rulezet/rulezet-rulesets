rule TTP_XOR_QUAD_CurrentVersionRun_b302 {
  strings:
    $key_b302 = { e0 6d [2] c4 63 [2] ef 4f [2] c1 6d [2] d5 76 [2] da 6c [2] c4 71 [2] c6 70 [2] dd 76 [2] c1 71 [2] dd 5e }

  condition:
    any of them
}