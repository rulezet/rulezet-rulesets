rule TTP_XOR_MULT_DOSStub_48b3 {
  strings:
    $key_48b3 = { 1c db [2] 68 c3 [2] 2f c1 [2] 68 d0 [2] 26 dc [2] 2a d6 [2] 3d dd [2] 26 93 [2] 1b }

  condition:
    any of them
}