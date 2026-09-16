rule TTP_XOR_QUAD_CurrentVersionRun_40a2 {
  strings:
    $key_40a2 = { 13 cd [2] 37 c3 [2] 1c ef [2] 32 cd [2] 26 d6 [2] 29 cc [2] 37 d1 [2] 35 d0 [2] 2e d6 [2] 32 d1 [2] 2e fe }

  condition:
    any of them
}