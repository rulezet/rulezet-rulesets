rule TTP_XOR_MULT_DOSStub_3994 {
  strings:
    $key_3994 = { 6d fc [2] 19 e4 [2] 5e e6 [2] 19 f7 [2] 57 fb [2] 5b f1 [2] 4c fa [2] 57 b4 [2] 6a }

  condition:
    any of them
}