rule TTP_XOR_QUAD_CurrentVersionRun_b6ff {
  strings:
    $key_b6ff = { e5 90 [2] c1 9e [2] ea b2 [2] c4 90 [2] d0 8b [2] df 91 [2] c1 8c [2] c3 8d [2] d8 8b [2] c4 8c [2] d8 a3 }

  condition:
    any of them
}