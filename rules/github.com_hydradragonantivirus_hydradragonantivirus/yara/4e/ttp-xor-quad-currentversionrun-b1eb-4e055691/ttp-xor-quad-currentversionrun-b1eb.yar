rule TTP_XOR_QUAD_CurrentVersionRun_b1eb {
  strings:
    $key_b1eb = { e2 84 [2] c6 8a [2] ed a6 [2] c3 84 [2] d7 9f [2] d8 85 [2] c6 98 [2] c4 99 [2] df 9f [2] c3 98 [2] df b7 }

  condition:
    any of them
}