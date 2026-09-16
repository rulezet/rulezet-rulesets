rule TTP_XOR_QUAD_CurrentVersionRun_b629 {
  strings:
    $key_b629 = { e5 46 [2] c1 48 [2] ea 64 [2] c4 46 [2] d0 5d [2] df 47 [2] c1 5a [2] c3 5b [2] d8 5d [2] c4 5a [2] d8 75 }

  condition:
    any of them
}