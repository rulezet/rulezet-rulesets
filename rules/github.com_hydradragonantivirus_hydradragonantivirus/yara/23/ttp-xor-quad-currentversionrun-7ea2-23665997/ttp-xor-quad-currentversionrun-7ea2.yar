rule TTP_XOR_QUAD_CurrentVersionRun_7ea2 {
  strings:
    $key_7ea2 = { 2d cd [2] 09 c3 [2] 22 ef [2] 0c cd [2] 18 d6 [2] 17 cc [2] 09 d1 [2] 0b d0 [2] 10 d6 [2] 0c d1 [2] 10 fe }

  condition:
    any of them
}