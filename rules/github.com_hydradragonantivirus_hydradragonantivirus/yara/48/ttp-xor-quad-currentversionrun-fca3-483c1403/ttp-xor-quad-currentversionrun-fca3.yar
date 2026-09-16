rule TTP_XOR_QUAD_CurrentVersionRun_fca3 {
  strings:
    $key_fca3 = { af cc [2] 8b c2 [2] a0 ee [2] 8e cc [2] 9a d7 [2] 95 cd [2] 8b d0 [2] 89 d1 [2] 92 d7 [2] 8e d0 [2] 92 ff }

  condition:
    any of them
}