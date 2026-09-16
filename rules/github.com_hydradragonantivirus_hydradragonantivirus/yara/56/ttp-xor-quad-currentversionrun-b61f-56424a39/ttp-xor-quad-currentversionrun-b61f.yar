rule TTP_XOR_QUAD_CurrentVersionRun_b61f {
  strings:
    $key_b61f = { e5 70 [2] c1 7e [2] ea 52 [2] c4 70 [2] d0 6b [2] df 71 [2] c1 6c [2] c3 6d [2] d8 6b [2] c4 6c [2] d8 43 }

  condition:
    any of them
}