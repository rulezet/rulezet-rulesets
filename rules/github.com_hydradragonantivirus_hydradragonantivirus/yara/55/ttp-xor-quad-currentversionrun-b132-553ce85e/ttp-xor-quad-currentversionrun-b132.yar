rule TTP_XOR_QUAD_CurrentVersionRun_b132 {
  strings:
    $key_b132 = { e2 5d [2] c6 53 [2] ed 7f [2] c3 5d [2] d7 46 [2] d8 5c [2] c6 41 [2] c4 40 [2] df 46 [2] c3 41 [2] df 6e }

  condition:
    any of them
}