rule TTP_XOR_MULT_DOSStub_d894 {
  strings:
    $key_d894 = { 8c fc [2] f8 e4 [2] bf e6 [2] f8 f7 [2] b6 fb [2] ba f1 [2] ad fa [2] b6 b4 [2] 8b }

  condition:
    any of them
}