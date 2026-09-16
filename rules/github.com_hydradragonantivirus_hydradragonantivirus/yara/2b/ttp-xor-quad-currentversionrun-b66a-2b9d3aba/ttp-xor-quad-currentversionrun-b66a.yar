rule TTP_XOR_QUAD_CurrentVersionRun_b66a {
  strings:
    $key_b66a = { e5 05 [2] c1 0b [2] ea 27 [2] c4 05 [2] d0 1e [2] df 04 [2] c1 19 [2] c3 18 [2] d8 1e [2] c4 19 [2] d8 36 }

  condition:
    any of them
}