rule TTP_XOR_QUAD_CurrentVersionRun_f4a2 {
  strings:
    $key_f4a2 = { a7 cd [2] 83 c3 [2] a8 ef [2] 86 cd [2] 92 d6 [2] 9d cc [2] 83 d1 [2] 81 d0 [2] 9a d6 [2] 86 d1 [2] 9a fe }

  condition:
    any of them
}