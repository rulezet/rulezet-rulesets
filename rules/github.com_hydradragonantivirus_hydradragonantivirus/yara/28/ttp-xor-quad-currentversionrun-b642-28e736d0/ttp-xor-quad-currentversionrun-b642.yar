rule TTP_XOR_QUAD_CurrentVersionRun_b642 {
  strings:
    $key_b642 = { e5 2d [2] c1 23 [2] ea 0f [2] c4 2d [2] d0 36 [2] df 2c [2] c1 31 [2] c3 30 [2] d8 36 [2] c4 31 [2] d8 1e }

  condition:
    any of them
}