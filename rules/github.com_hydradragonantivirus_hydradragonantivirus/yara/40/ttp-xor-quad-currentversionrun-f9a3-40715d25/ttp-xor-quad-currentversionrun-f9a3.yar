rule TTP_XOR_QUAD_CurrentVersionRun_f9a3 {
  strings:
    $key_f9a3 = { aa cc [2] 8e c2 [2] a5 ee [2] 8b cc [2] 9f d7 [2] 90 cd [2] 8e d0 [2] 8c d1 [2] 97 d7 [2] 8b d0 [2] 97 ff }

  condition:
    any of them
}