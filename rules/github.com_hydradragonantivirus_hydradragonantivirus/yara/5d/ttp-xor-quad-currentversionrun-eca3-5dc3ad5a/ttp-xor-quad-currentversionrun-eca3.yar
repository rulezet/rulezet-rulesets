rule TTP_XOR_QUAD_CurrentVersionRun_eca3 {
  strings:
    $key_eca3 = { bf cc [2] 9b c2 [2] b0 ee [2] 9e cc [2] 8a d7 [2] 85 cd [2] 9b d0 [2] 99 d1 [2] 82 d7 [2] 9e d0 [2] 82 ff }

  condition:
    any of them
}