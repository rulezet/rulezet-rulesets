rule TTP_XOR_QUAD_CurrentVersionRun_7fa2 {
  strings:
    $key_7fa2 = { 2c cd [2] 08 c3 [2] 23 ef [2] 0d cd [2] 19 d6 [2] 16 cc [2] 08 d1 [2] 0a d0 [2] 11 d6 [2] 0d d1 [2] 11 fe }

  condition:
    any of them
}