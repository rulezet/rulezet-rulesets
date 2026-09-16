rule TTP_XOR_QUAD_CurrentVersionRun_b672 {
  strings:
    $key_b672 = { e5 1d [2] c1 13 [2] ea 3f [2] c4 1d [2] d0 06 [2] df 1c [2] c1 01 [2] c3 00 [2] d8 06 [2] c4 01 [2] d8 2e }

  condition:
    any of them
}