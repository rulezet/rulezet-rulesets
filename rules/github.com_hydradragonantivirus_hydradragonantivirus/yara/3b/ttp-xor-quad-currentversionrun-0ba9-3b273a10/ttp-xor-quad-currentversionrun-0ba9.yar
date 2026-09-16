rule TTP_XOR_QUAD_CurrentVersionRun_0ba9 {
  strings:
    $key_0ba9 = { 58 c6 [2] 7c c8 [2] 57 e4 [2] 79 c6 [2] 6d dd [2] 62 c7 [2] 7c da [2] 7e db [2] 65 dd [2] 79 da [2] 65 f5 }

  condition:
    any of them
}