rule TTP_XOR_QUAD_CurrentVersionRun_ceab {
  strings:
    $key_ceab = { 9d c4 [2] b9 ca [2] 92 e6 [2] bc c4 [2] a8 df [2] a7 c5 [2] b9 d8 [2] bb d9 [2] a0 df [2] bc d8 [2] a0 f7 }

  condition:
    any of them
}