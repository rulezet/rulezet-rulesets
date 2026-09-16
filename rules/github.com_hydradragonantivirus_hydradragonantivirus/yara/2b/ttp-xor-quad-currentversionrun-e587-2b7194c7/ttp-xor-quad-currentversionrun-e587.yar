rule TTP_XOR_QUAD_CurrentVersionRun_e587 {
  strings:
    $key_e587 = { b6 e8 [2] 92 e6 [2] b9 ca [2] 97 e8 [2] 83 f3 [2] 8c e9 [2] 92 f4 [2] 90 f5 [2] 8b f3 [2] 97 f4 [2] 8b db }

  condition:
    any of them
}