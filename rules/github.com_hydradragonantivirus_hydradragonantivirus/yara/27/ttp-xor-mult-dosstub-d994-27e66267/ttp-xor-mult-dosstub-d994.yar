rule TTP_XOR_MULT_DOSStub_d994 {
  strings:
    $key_d994 = { 8d fc [2] f9 e4 [2] be e6 [2] f9 f7 [2] b7 fb [2] bb f1 [2] ac fa [2] b7 b4 [2] 8a }

  condition:
    any of them
}