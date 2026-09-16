rule TTP_XOR_QUAD_CurrentVersionRun_e89a {
  strings:
    $key_e89a = { bb f5 [2] 9f fb [2] b4 d7 [2] 9a f5 [2] 8e ee [2] 81 f4 [2] 9f e9 [2] 9d e8 [2] 86 ee [2] 9a e9 [2] 86 c6 }

  condition:
    any of them
}