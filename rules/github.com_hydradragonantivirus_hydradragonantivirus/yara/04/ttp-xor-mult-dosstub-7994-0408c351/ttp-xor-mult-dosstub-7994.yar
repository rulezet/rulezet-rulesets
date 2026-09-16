rule TTP_XOR_MULT_DOSStub_7994 {
  strings:
    $key_7994 = { 2d fc [2] 59 e4 [2] 1e e6 [2] 59 f7 [2] 17 fb [2] 1b f1 [2] 0c fa [2] 17 b4 [2] 2a }

  condition:
    any of them
}