rule TTP_XOR_QUAD_CurrentVersionRun_3aa2 {
  strings:
    $key_3aa2 = { 69 cd [2] 4d c3 [2] 66 ef [2] 48 cd [2] 5c d6 [2] 53 cc [2] 4d d1 [2] 4f d0 [2] 54 d6 [2] 48 d1 [2] 54 fe }

  condition:
    any of them
}