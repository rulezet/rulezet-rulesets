rule TTP_XOR_QUAD_CurrentVersionRun_b60f {
  strings:
    $key_b60f = { e5 60 [2] c1 6e [2] ea 42 [2] c4 60 [2] d0 7b [2] df 61 [2] c1 7c [2] c3 7d [2] d8 7b [2] c4 7c [2] d8 53 }

  condition:
    any of them
}