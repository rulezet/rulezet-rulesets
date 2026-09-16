rule TTP_XOR_QUAD_CurrentVersionRun_e99a {
  strings:
    $key_e99a = { ba f5 [2] 9e fb [2] b5 d7 [2] 9b f5 [2] 8f ee [2] 80 f4 [2] 9e e9 [2] 9c e8 [2] 87 ee [2] 9b e9 [2] 87 c6 }

  condition:
    any of them
}