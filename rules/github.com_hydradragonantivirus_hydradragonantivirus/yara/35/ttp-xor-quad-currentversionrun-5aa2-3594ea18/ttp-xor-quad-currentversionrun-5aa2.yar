rule TTP_XOR_QUAD_CurrentVersionRun_5aa2 {
  strings:
    $key_5aa2 = { 09 cd [2] 2d c3 [2] 06 ef [2] 28 cd [2] 3c d6 [2] 33 cc [2] 2d d1 [2] 2f d0 [2] 34 d6 [2] 28 d1 [2] 34 fe }

  condition:
    any of them
}