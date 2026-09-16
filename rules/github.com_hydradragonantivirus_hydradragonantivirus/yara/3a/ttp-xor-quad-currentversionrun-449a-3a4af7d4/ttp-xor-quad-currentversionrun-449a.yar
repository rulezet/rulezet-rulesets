rule TTP_XOR_QUAD_CurrentVersionRun_449a {
  strings:
    $key_449a = { 17 f5 [2] 33 fb [2] 18 d7 [2] 36 f5 [2] 22 ee [2] 2d f4 [2] 33 e9 [2] 31 e8 [2] 2a ee [2] 36 e9 [2] 2a c6 }

  condition:
    any of them
}