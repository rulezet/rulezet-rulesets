rule TTP_XOR_QUAD_CurrentVersionRun_1ea9 {
  strings:
    $key_1ea9 = { 4d c6 [2] 69 c8 [2] 42 e4 [2] 6c c6 [2] 78 dd [2] 77 c7 [2] 69 da [2] 6b db [2] 70 dd [2] 6c da [2] 70 f5 }

  condition:
    any of them
}