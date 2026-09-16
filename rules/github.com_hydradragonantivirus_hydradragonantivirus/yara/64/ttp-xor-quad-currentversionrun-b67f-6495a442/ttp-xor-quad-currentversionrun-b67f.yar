rule TTP_XOR_QUAD_CurrentVersionRun_b67f {
  strings:
    $key_b67f = { e5 10 [2] c1 1e [2] ea 32 [2] c4 10 [2] d0 0b [2] df 11 [2] c1 0c [2] c3 0d [2] d8 0b [2] c4 0c [2] d8 23 }

  condition:
    any of them
}