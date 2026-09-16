rule TTP_XOR_MULT_DOSStub_c694 {
  strings:
    $key_c694 = { 92 fc [2] e6 e4 [2] a1 e6 [2] e6 f7 [2] a8 fb [2] a4 f1 [2] b3 fa [2] a8 b4 [2] 95 }

  condition:
    any of them
}