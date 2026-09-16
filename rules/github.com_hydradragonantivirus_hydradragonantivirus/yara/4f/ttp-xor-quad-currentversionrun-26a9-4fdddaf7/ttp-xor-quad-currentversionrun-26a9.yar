rule TTP_XOR_QUAD_CurrentVersionRun_26a9 {
  strings:
    $key_26a9 = { 75 c6 [2] 51 c8 [2] 7a e4 [2] 54 c6 [2] 40 dd [2] 4f c7 [2] 51 da [2] 53 db [2] 48 dd [2] 54 da [2] 48 f5 }

  condition:
    any of them
}