rule TTP_XOR_QUAD_CurrentVersionRun_04a2 {
  strings:
    $key_04a2 = { 57 cd [2] 73 c3 [2] 58 ef [2] 76 cd [2] 62 d6 [2] 6d cc [2] 73 d1 [2] 71 d0 [2] 6a d6 [2] 76 d1 [2] 6a fe }

  condition:
    any of them
}