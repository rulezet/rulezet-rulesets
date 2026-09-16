rule TTP_XOR_QUAD_CurrentVersionRun_b662 {
  strings:
    $key_b662 = { e5 0d [2] c1 03 [2] ea 2f [2] c4 0d [2] d0 16 [2] df 0c [2] c1 11 [2] c3 10 [2] d8 16 [2] c4 11 [2] d8 3e }

  condition:
    any of them
}