rule TTP_XOR_QUAD_CurrentVersionRun_b67a {
  strings:
    $key_b67a = { e5 15 [2] c1 1b [2] ea 37 [2] c4 15 [2] d0 0e [2] df 14 [2] c1 09 [2] c3 08 [2] d8 0e [2] c4 09 [2] d8 26 }

  condition:
    any of them
}