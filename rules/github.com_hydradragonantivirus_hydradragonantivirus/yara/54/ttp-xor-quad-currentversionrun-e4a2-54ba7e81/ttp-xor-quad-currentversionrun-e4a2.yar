rule TTP_XOR_QUAD_CurrentVersionRun_e4a2 {
  strings:
    $key_e4a2 = { b7 cd [2] 93 c3 [2] b8 ef [2] 96 cd [2] 82 d6 [2] 8d cc [2] 93 d1 [2] 91 d0 [2] 8a d6 [2] 96 d1 [2] 8a fe }

  condition:
    any of them
}