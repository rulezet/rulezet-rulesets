rule TTP_XOR_QUAD_CurrentVersionRun_dca9 {
  strings:
    $key_dca9 = { 8f c6 [2] ab c8 [2] 80 e4 [2] ae c6 [2] ba dd [2] b5 c7 [2] ab da [2] a9 db [2] b2 dd [2] ae da [2] b2 f5 }

  condition:
    any of them
}