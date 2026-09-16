rule TTP_XOR_QUAD_CurrentVersionRun_339a {
  strings:
    $key_339a = { 60 f5 [2] 44 fb [2] 6f d7 [2] 41 f5 [2] 55 ee [2] 5a f4 [2] 44 e9 [2] 46 e8 [2] 5d ee [2] 41 e9 [2] 5d c6 }

  condition:
    any of them
}