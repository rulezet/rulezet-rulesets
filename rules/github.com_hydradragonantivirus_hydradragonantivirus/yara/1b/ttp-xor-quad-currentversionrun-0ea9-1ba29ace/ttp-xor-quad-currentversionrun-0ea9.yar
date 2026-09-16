rule TTP_XOR_QUAD_CurrentVersionRun_0ea9 {
  strings:
    $key_0ea9 = { 5d c6 [2] 79 c8 [2] 52 e4 [2] 7c c6 [2] 68 dd [2] 67 c7 [2] 79 da [2] 7b db [2] 60 dd [2] 7c da [2] 60 f5 }

  condition:
    any of them
}