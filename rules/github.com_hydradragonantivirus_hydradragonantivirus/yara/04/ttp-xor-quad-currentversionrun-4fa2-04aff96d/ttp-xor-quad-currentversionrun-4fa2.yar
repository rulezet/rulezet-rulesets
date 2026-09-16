rule TTP_XOR_QUAD_CurrentVersionRun_4fa2 {
  strings:
    $key_4fa2 = { 1c cd [2] 38 c3 [2] 13 ef [2] 3d cd [2] 29 d6 [2] 26 cc [2] 38 d1 [2] 3a d0 [2] 21 d6 [2] 3d d1 [2] 21 fe }

  condition:
    any of them
}