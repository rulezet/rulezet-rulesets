rule TTP_XOR_QUAD_CurrentVersionRun_ef9a {
  strings:
    $key_ef9a = { bc f5 [2] 98 fb [2] b3 d7 [2] 9d f5 [2] 89 ee [2] 86 f4 [2] 98 e9 [2] 9a e8 [2] 81 ee [2] 9d e9 [2] 81 c6 }

  condition:
    any of them
}