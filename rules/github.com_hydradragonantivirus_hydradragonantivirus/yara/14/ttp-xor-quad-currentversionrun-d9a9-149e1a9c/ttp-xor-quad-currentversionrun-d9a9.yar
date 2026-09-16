rule TTP_XOR_QUAD_CurrentVersionRun_d9a9 {
  strings:
    $key_d9a9 = { 8a c6 [2] ae c8 [2] 85 e4 [2] ab c6 [2] bf dd [2] b0 c7 [2] ae da [2] ac db [2] b7 dd [2] ab da [2] b7 f5 }

  condition:
    any of them
}