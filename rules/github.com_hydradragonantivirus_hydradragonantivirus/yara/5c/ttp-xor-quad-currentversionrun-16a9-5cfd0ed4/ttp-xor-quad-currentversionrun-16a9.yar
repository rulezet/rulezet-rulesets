rule TTP_XOR_QUAD_CurrentVersionRun_16a9 {
  strings:
    $key_16a9 = { 45 c6 [2] 61 c8 [2] 4a e4 [2] 64 c6 [2] 70 dd [2] 7f c7 [2] 61 da [2] 63 db [2] 78 dd [2] 64 da [2] 78 f5 }

  condition:
    any of them
}