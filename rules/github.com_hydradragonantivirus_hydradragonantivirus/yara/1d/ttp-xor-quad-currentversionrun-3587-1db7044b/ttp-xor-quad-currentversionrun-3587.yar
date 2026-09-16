rule TTP_XOR_QUAD_CurrentVersionRun_3587 {
  strings:
    $key_3587 = { 66 e8 [2] 42 e6 [2] 69 ca [2] 47 e8 [2] 53 f3 [2] 5c e9 [2] 42 f4 [2] 40 f5 [2] 5b f3 [2] 47 f4 [2] 5b db }

  condition:
    any of them
}