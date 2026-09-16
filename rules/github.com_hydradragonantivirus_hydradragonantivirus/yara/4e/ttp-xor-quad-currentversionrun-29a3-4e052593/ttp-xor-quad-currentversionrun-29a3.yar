rule TTP_XOR_QUAD_CurrentVersionRun_29a3 {
  strings:
    $key_29a3 = { 7a cc [2] 5e c2 [2] 75 ee [2] 5b cc [2] 4f d7 [2] 40 cd [2] 5e d0 [2] 5c d1 [2] 47 d7 [2] 5b d0 [2] 47 ff }

  condition:
    any of them
}