rule TTP_XOR_QUAD_CurrentVersionRun_6fa2 {
  strings:
    $key_6fa2 = { 3c cd [2] 18 c3 [2] 33 ef [2] 1d cd [2] 09 d6 [2] 06 cc [2] 18 d1 [2] 1a d0 [2] 01 d6 [2] 1d d1 [2] 01 fe }

  condition:
    any of them
}