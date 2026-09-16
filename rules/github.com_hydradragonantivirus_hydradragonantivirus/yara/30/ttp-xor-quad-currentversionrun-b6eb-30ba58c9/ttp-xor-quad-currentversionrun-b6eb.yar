rule TTP_XOR_QUAD_CurrentVersionRun_b6eb {
  strings:
    $key_b6eb = { e5 84 [2] c1 8a [2] ea a6 [2] c4 84 [2] d0 9f [2] df 85 [2] c1 98 [2] c3 99 [2] d8 9f [2] c4 98 [2] d8 b7 }

  condition:
    any of them
}