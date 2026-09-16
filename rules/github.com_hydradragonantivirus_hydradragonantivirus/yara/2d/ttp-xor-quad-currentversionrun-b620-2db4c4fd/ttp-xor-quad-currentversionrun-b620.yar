rule TTP_XOR_QUAD_CurrentVersionRun_b620 {
  strings:
    $key_b620 = { e5 4f [2] c1 41 [2] ea 6d [2] c4 4f [2] d0 54 [2] df 4e [2] c1 53 [2] c3 52 [2] d8 54 [2] c4 53 [2] d8 7c }

  condition:
    any of them
}