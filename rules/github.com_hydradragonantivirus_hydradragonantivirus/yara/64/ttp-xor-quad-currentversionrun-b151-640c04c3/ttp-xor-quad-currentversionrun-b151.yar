rule TTP_XOR_QUAD_CurrentVersionRun_b151 {
  strings:
    $key_b151 = { e2 3e [2] c6 30 [2] ed 1c [2] c3 3e [2] d7 25 [2] d8 3f [2] c6 22 [2] c4 23 [2] df 25 [2] c3 22 [2] df 0d }

  condition:
    any of them
}