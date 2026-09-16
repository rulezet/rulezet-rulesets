rule TTP_XOR_MULT_DOSStub_c494 {
  strings:
    $key_c494 = { 90 fc [2] e4 e4 [2] a3 e6 [2] e4 f7 [2] aa fb [2] a6 f1 [2] b1 fa [2] aa b4 [2] 97 }

  condition:
    any of them
}