rule TTP_XOR_QUAD_CurrentVersionRun_ffa2 {
  strings:
    $key_ffa2 = { ac cd [2] 88 c3 [2] a3 ef [2] 8d cd [2] 99 d6 [2] 96 cc [2] 88 d1 [2] 8a d0 [2] 91 d6 [2] 8d d1 [2] 91 fe }

  condition:
    any of them
}