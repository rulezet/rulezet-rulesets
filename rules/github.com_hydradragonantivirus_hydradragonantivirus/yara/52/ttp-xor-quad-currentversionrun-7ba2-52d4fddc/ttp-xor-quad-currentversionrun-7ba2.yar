rule TTP_XOR_QUAD_CurrentVersionRun_7ba2 {
  strings:
    $key_7ba2 = { 28 cd [2] 0c c3 [2] 27 ef [2] 09 cd [2] 1d d6 [2] 12 cc [2] 0c d1 [2] 0e d0 [2] 15 d6 [2] 09 d1 [2] 15 fe }

  condition:
    any of them
}