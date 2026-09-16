rule TTP_XOR_QUAD_CurrentVersionRun_b3e2 {
  strings:
    $key_b3e2 = { e0 8d [2] c4 83 [2] ef af [2] c1 8d [2] d5 96 [2] da 8c [2] c4 91 [2] c6 90 [2] dd 96 [2] c1 91 [2] dd be }

  condition:
    any of them
}