rule TTP_XOR_QUAD_CurrentVersionRun_b432 {
  strings:
    $key_b432 = { e7 5d [2] c3 53 [2] e8 7f [2] c6 5d [2] d2 46 [2] dd 5c [2] c3 41 [2] c1 40 [2] da 46 [2] c6 41 [2] da 6e }

  condition:
    any of them
}