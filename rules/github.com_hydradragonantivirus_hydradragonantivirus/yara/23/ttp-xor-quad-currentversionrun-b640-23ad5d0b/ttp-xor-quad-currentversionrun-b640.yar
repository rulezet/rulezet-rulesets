rule TTP_XOR_QUAD_CurrentVersionRun_b640 {
  strings:
    $key_b640 = { e5 2f [2] c1 21 [2] ea 0d [2] c4 2f [2] d0 34 [2] df 2e [2] c1 33 [2] c3 32 [2] d8 34 [2] c4 33 [2] d8 1c }

  condition:
    any of them
}