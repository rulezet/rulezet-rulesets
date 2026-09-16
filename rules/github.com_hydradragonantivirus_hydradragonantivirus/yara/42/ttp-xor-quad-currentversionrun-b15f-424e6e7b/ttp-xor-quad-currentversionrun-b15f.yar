rule TTP_XOR_QUAD_CurrentVersionRun_b15f {
  strings:
    $key_b15f = { e2 30 [2] c6 3e [2] ed 12 [2] c3 30 [2] d7 2b [2] d8 31 [2] c6 2c [2] c4 2d [2] df 2b [2] c3 2c [2] df 03 }

  condition:
    any of them
}