rule TTP_XOR_QUAD_CurrentVersionRun_0fa2 {
  strings:
    $key_0fa2 = { 5c cd [2] 78 c3 [2] 53 ef [2] 7d cd [2] 69 d6 [2] 66 cc [2] 78 d1 [2] 7a d0 [2] 61 d6 [2] 7d d1 [2] 61 fe }

  condition:
    any of them
}