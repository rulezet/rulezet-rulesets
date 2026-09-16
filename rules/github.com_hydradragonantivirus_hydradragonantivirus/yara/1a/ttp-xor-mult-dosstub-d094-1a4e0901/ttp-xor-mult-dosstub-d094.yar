rule TTP_XOR_MULT_DOSStub_d094 {
  strings:
    $key_d094 = { 84 fc [2] f0 e4 [2] b7 e6 [2] f0 f7 [2] be fb [2] b2 f1 [2] a5 fa [2] be b4 [2] 83 }

  condition:
    any of them
}