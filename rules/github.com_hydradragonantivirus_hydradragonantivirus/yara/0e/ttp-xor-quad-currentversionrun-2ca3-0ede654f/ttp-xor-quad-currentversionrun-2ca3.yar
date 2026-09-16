rule TTP_XOR_QUAD_CurrentVersionRun_2ca3 {
  strings:
    $key_2ca3 = { 7f cc [2] 5b c2 [2] 70 ee [2] 5e cc [2] 4a d7 [2] 45 cd [2] 5b d0 [2] 59 d1 [2] 42 d7 [2] 5e d0 [2] 42 ff }

  condition:
    any of them
}