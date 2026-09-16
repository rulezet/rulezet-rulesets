rule TTP_XOR_QUAD_CurrentVersionRun_d89a {
  strings:
    $key_d89a = { 8b f5 [2] af fb [2] 84 d7 [2] aa f5 [2] be ee [2] b1 f4 [2] af e9 [2] ad e8 [2] b6 ee [2] aa e9 [2] b6 c6 }

  condition:
    any of them
}