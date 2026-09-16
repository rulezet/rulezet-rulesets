rule TTP_XOR_MULT_DOSStub_c994 {
  strings:
    $key_c994 = { 9d fc [2] e9 e4 [2] ae e6 [2] e9 f7 [2] a7 fb [2] ab f1 [2] bc fa [2] a7 b4 [2] 9a }

  condition:
    any of them
}