rule TTP_XOR_QUAD_CurrentVersionRun_1ca3 {
  strings:
    $key_1ca3 = { 4f cc [2] 6b c2 [2] 40 ee [2] 6e cc [2] 7a d7 [2] 75 cd [2] 6b d0 [2] 69 d1 [2] 72 d7 [2] 6e d0 [2] 72 ff }

  condition:
    any of them
}