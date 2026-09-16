rule TTP_XOR_QUAD_CurrentVersionRun_b678 {
  strings:
    $key_b678 = { e5 17 [2] c1 19 [2] ea 35 [2] c4 17 [2] d0 0c [2] df 16 [2] c1 0b [2] c3 0a [2] d8 0c [2] c4 0b [2] d8 24 }

  condition:
    any of them
}