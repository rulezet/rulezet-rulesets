rule TTP_XOR_QUAD_CurrentVersionRun_6aa2 {
  strings:
    $key_6aa2 = { 39 cd [2] 1d c3 [2] 36 ef [2] 18 cd [2] 0c d6 [2] 03 cc [2] 1d d1 [2] 1f d0 [2] 04 d6 [2] 18 d1 [2] 04 fe }

  condition:
    any of them
}