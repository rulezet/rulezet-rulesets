rule TTP_XOR_QUAD_CurrentVersionRun_b2ea {
  strings:
    $key_b2ea = { e1 85 [2] c5 8b [2] ee a7 [2] c0 85 [2] d4 9e [2] db 84 [2] c5 99 [2] c7 98 [2] dc 9e [2] c0 99 [2] dc b6 }

  condition:
    any of them
}