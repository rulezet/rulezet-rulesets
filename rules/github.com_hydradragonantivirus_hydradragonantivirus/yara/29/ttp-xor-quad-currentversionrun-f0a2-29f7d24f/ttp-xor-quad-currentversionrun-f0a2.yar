rule TTP_XOR_QUAD_CurrentVersionRun_f0a2 {
  strings:
    $key_f0a2 = { a3 cd [2] 87 c3 [2] ac ef [2] 82 cd [2] 96 d6 [2] 99 cc [2] 87 d1 [2] 85 d0 [2] 9e d6 [2] 82 d1 [2] 9e fe }

  condition:
    any of them
}