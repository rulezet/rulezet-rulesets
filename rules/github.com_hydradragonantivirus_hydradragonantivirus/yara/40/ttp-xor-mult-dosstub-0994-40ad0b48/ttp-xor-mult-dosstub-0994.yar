rule TTP_XOR_MULT_DOSStub_0994 {
  strings:
    $key_0994 = { 5d fc [2] 29 e4 [2] 6e e6 [2] 29 f7 [2] 67 fb [2] 6b f1 [2] 7c fa [2] 67 b4 [2] 5a }

  condition:
    any of them
}