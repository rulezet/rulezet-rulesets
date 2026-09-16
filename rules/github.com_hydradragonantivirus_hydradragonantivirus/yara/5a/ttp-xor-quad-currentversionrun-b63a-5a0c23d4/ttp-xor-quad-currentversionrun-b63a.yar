rule TTP_XOR_QUAD_CurrentVersionRun_b63a {
  strings:
    $key_b63a = { e5 55 [2] c1 5b [2] ea 77 [2] c4 55 [2] d0 4e [2] df 54 [2] c1 49 [2] c3 48 [2] d8 4e [2] c4 49 [2] d8 66 }

  condition:
    any of them
}