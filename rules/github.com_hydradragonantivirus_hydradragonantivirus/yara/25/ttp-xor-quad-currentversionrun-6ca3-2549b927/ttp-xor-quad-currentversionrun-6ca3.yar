rule TTP_XOR_QUAD_CurrentVersionRun_6ca3 {
  strings:
    $key_6ca3 = { 3f cc [2] 1b c2 [2] 30 ee [2] 1e cc [2] 0a d7 [2] 05 cd [2] 1b d0 [2] 19 d1 [2] 02 d7 [2] 1e d0 [2] 02 ff }

  condition:
    any of them
}