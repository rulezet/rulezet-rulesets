rule TTP_XOR_QUAD_CurrentVersionRun_b1ea {
  strings:
    $key_b1ea = { e2 85 [2] c6 8b [2] ed a7 [2] c3 85 [2] d7 9e [2] d8 84 [2] c6 99 [2] c4 98 [2] df 9e [2] c3 99 [2] df b6 }

  condition:
    any of them
}