rule TTP_XOR_QUAD_CurrentVersionRun_b2e4 {
  strings:
    $key_b2e4 = { e1 8b [2] c5 85 [2] ee a9 [2] c0 8b [2] d4 90 [2] db 8a [2] c5 97 [2] c7 96 [2] dc 90 [2] c0 97 [2] dc b8 }

  condition:
    any of them
}