rule TTP_XOR_QUAD_CurrentVersionRun_b611 {
  strings:
    $key_b611 = { e5 7e [2] c1 70 [2] ea 5c [2] c4 7e [2] d0 65 [2] df 7f [2] c1 62 [2] c3 63 [2] d8 65 [2] c4 62 [2] d8 4d }

  condition:
    any of them
}