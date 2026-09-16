rule TTP_XOR_QUAD_CurrentVersionRun_3ba2 {
  strings:
    $key_3ba2 = { 68 cd [2] 4c c3 [2] 67 ef [2] 49 cd [2] 5d d6 [2] 52 cc [2] 4c d1 [2] 4e d0 [2] 55 d6 [2] 49 d1 [2] 55 fe }

  condition:
    any of them
}