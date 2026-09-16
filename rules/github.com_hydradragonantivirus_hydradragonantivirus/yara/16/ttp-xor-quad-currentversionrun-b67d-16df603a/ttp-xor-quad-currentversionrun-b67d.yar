rule TTP_XOR_QUAD_CurrentVersionRun_b67d {
  strings:
    $key_b67d = { e5 12 [2] c1 1c [2] ea 30 [2] c4 12 [2] d0 09 [2] df 13 [2] c1 0e [2] c3 0f [2] d8 09 [2] c4 0e [2] d8 21 }

  condition:
    any of them
}