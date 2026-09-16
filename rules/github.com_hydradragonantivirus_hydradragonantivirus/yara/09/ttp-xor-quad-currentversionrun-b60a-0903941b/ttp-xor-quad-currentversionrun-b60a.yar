rule TTP_XOR_QUAD_CurrentVersionRun_b60a {
  strings:
    $key_b60a = { e5 65 [2] c1 6b [2] ea 47 [2] c4 65 [2] d0 7e [2] df 64 [2] c1 79 [2] c3 78 [2] d8 7e [2] c4 79 [2] d8 56 }

  condition:
    any of them
}