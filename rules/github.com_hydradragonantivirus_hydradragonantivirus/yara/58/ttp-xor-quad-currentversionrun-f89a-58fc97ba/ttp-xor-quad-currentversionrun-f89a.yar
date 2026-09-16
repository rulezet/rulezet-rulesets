rule TTP_XOR_QUAD_CurrentVersionRun_f89a {
  strings:
    $key_f89a = { ab f5 [2] 8f fb [2] a4 d7 [2] 8a f5 [2] 9e ee [2] 91 f4 [2] 8f e9 [2] 8d e8 [2] 96 ee [2] 8a e9 [2] 96 c6 }

  condition:
    any of them
}