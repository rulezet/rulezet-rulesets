rule TTP_XOR_QUAD_CurrentVersionRun_7ba3 {
  strings:
    $key_7ba3 = { 28 cc [2] 0c c2 [2] 27 ee [2] 09 cc [2] 1d d7 [2] 12 cd [2] 0c d0 [2] 0e d1 [2] 15 d7 [2] 09 d0 [2] 15 ff }

  condition:
    any of them
}