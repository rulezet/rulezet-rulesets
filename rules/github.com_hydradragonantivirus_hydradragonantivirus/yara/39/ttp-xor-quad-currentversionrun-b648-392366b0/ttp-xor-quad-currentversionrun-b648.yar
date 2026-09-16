rule TTP_XOR_QUAD_CurrentVersionRun_b648 {
  strings:
    $key_b648 = { e5 27 [2] c1 29 [2] ea 05 [2] c4 27 [2] d0 3c [2] df 26 [2] c1 3b [2] c3 3a [2] d8 3c [2] c4 3b [2] d8 14 }

  condition:
    any of them
}