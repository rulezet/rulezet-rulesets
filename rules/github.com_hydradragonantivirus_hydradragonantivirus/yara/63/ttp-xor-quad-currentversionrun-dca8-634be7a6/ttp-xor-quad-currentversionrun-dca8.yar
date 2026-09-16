rule TTP_XOR_QUAD_CurrentVersionRun_dca8 {
  strings:
    $key_dca8 = { 8f c7 [2] ab c9 [2] 80 e5 [2] ae c7 [2] ba dc [2] b5 c6 [2] ab db [2] a9 da [2] b2 dc [2] ae db [2] b2 f4 }

  condition:
    any of them
}