rule TTP_XOR_QUAD_CurrentVersionRun_6ba9 {
  strings:
    $key_6ba9 = { 38 c6 [2] 1c c8 [2] 37 e4 [2] 19 c6 [2] 0d dd [2] 02 c7 [2] 1c da [2] 1e db [2] 05 dd [2] 19 da [2] 05 f5 }

  condition:
    any of them
}