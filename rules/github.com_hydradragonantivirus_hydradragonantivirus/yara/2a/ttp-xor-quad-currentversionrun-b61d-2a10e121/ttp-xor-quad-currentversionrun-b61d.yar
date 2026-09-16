rule TTP_XOR_QUAD_CurrentVersionRun_b61d {
  strings:
    $key_b61d = { e5 72 [2] c1 7c [2] ea 50 [2] c4 72 [2] d0 69 [2] df 73 [2] c1 6e [2] c3 6f [2] d8 69 [2] c4 6e [2] d8 41 }

  condition:
    any of them
}