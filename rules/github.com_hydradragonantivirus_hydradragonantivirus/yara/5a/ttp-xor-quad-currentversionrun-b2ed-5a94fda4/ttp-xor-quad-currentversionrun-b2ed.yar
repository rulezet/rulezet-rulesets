rule TTP_XOR_QUAD_CurrentVersionRun_b2ed {
  strings:
    $key_b2ed = { e1 82 [2] c5 8c [2] ee a0 [2] c0 82 [2] d4 99 [2] db 83 [2] c5 9e [2] c7 9f [2] dc 99 [2] c0 9e [2] dc b1 }

  condition:
    any of them
}