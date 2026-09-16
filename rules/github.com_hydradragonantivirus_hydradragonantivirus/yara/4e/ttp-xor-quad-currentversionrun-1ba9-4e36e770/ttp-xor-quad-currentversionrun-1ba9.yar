rule TTP_XOR_QUAD_CurrentVersionRun_1ba9 {
  strings:
    $key_1ba9 = { 48 c6 [2] 6c c8 [2] 47 e4 [2] 69 c6 [2] 7d dd [2] 72 c7 [2] 6c da [2] 6e db [2] 75 dd [2] 69 da [2] 75 f5 }

  condition:
    any of them
}