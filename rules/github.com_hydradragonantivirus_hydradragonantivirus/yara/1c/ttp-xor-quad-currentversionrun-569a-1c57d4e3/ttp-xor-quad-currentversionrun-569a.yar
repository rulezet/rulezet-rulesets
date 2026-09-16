rule TTP_XOR_QUAD_CurrentVersionRun_569a {
  strings:
    $key_569a = { 05 f5 [2] 21 fb [2] 0a d7 [2] 24 f5 [2] 30 ee [2] 3f f4 [2] 21 e9 [2] 23 e8 [2] 38 ee [2] 24 e9 [2] 38 c6 }

  condition:
    any of them
}