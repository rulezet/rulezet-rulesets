rule TTP_XOR_QUAD_CurrentVersionRun_0ca3 {
  strings:
    $key_0ca3 = { 5f cc [2] 7b c2 [2] 50 ee [2] 7e cc [2] 6a d7 [2] 65 cd [2] 7b d0 [2] 79 d1 [2] 62 d7 [2] 7e d0 [2] 62 ff }

  condition:
    any of them
}