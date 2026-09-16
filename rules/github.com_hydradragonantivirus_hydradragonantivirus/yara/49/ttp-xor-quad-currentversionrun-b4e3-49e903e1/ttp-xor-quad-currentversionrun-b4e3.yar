rule TTP_XOR_QUAD_CurrentVersionRun_b4e3 {
  strings:
    $key_b4e3 = { e7 8c [2] c3 82 [2] e8 ae [2] c6 8c [2] d2 97 [2] dd 8d [2] c3 90 [2] c1 91 [2] da 97 [2] c6 90 [2] da bf }

  condition:
    any of them
}