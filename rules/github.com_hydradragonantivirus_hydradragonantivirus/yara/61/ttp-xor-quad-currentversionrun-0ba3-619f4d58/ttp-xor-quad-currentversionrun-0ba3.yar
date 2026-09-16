rule TTP_XOR_QUAD_CurrentVersionRun_0ba3 {
  strings:
    $key_0ba3 = { 58 cc [2] 7c c2 [2] 57 ee [2] 79 cc [2] 6d d7 [2] 62 cd [2] 7c d0 [2] 7e d1 [2] 65 d7 [2] 79 d0 [2] 65 ff }

  condition:
    any of them
}