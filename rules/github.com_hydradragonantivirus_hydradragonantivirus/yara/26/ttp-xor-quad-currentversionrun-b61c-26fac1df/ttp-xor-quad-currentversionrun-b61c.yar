rule TTP_XOR_QUAD_CurrentVersionRun_b61c {
  strings:
    $key_b61c = { e5 73 [2] c1 7d [2] ea 51 [2] c4 73 [2] d0 68 [2] df 72 [2] c1 6f [2] c3 6e [2] d8 68 [2] c4 6f [2] d8 40 }

  condition:
    any of them
}