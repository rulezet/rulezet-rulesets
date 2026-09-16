rule TTP_XOR_MULT_DOSStub_ec94 {
  strings:
    $key_ec94 = { b8 fc [2] cc e4 [2] 8b e6 [2] cc f7 [2] 82 fb [2] 8e f1 [2] 99 fa [2] 82 b4 [2] bf }

  condition:
    any of them
}