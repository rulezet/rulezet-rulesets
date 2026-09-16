rule TTP_XOR_QUAD_CurrentVersionRun_669a {
  strings:
    $key_669a = { 35 f5 [2] 11 fb [2] 3a d7 [2] 14 f5 [2] 00 ee [2] 0f f4 [2] 11 e9 [2] 13 e8 [2] 08 ee [2] 14 e9 [2] 08 c6 }

  condition:
    any of them
}