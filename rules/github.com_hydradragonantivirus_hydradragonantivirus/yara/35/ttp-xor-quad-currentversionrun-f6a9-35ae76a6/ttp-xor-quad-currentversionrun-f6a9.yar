rule TTP_XOR_QUAD_CurrentVersionRun_f6a9 {
  strings:
    $key_f6a9 = { a5 c6 [2] 81 c8 [2] aa e4 [2] 84 c6 [2] 90 dd [2] 9f c7 [2] 81 da [2] 83 db [2] 98 dd [2] 84 da [2] 98 f5 }

  condition:
    any of them
}