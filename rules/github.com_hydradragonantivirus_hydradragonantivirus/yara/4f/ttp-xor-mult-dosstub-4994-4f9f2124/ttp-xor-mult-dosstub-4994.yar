rule TTP_XOR_MULT_DOSStub_4994 {
  strings:
    $key_4994 = { 1d fc [2] 69 e4 [2] 2e e6 [2] 69 f7 [2] 27 fb [2] 2b f1 [2] 3c fa [2] 27 b4 [2] 1a }

  condition:
    any of them
}