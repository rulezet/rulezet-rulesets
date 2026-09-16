rule TTP_XOR_QUAD_CurrentVersionRun_b66d {
  strings:
    $key_b66d = { e5 02 [2] c1 0c [2] ea 20 [2] c4 02 [2] d0 19 [2] df 03 [2] c1 1e [2] c3 1f [2] d8 19 [2] c4 1e [2] d8 31 }

  condition:
    any of them
}