rule TTP_XOR_QUAD_CurrentVersionRun_2ba2 {
  strings:
    $key_2ba2 = { 78 cd [2] 5c c3 [2] 77 ef [2] 59 cd [2] 4d d6 [2] 42 cc [2] 5c d1 [2] 5e d0 [2] 45 d6 [2] 59 d1 [2] 45 fe }

  condition:
    any of them
}