rule TTP_XOR_QUAD_CurrentVersionRun_d5a2 {
  strings:
    $key_d5a2 = { 86 cd [2] a2 c3 [2] 89 ef [2] a7 cd [2] b3 d6 [2] bc cc [2] a2 d1 [2] a0 d0 [2] bb d6 [2] a7 d1 [2] bb fe }

  condition:
    any of them
}