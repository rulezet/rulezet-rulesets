rule TTP_XOR_QUAD_CurrentVersionRun_b2e9 {
  strings:
    $key_b2e9 = { e1 86 [2] c5 88 [2] ee a4 [2] c0 86 [2] d4 9d [2] db 87 [2] c5 9a [2] c7 9b [2] dc 9d [2] c0 9a [2] dc b5 }

  condition:
    any of them
}