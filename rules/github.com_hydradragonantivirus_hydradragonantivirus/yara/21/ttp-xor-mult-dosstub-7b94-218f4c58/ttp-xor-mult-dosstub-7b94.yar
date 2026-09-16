rule TTP_XOR_MULT_DOSStub_7b94 {
  strings:
    $key_7b94 = { 2f fc [2] 5b e4 [2] 1c e6 [2] 5b f7 [2] 15 fb [2] 19 f1 [2] 0e fa [2] 15 b4 [2] 28 }

  condition:
    any of them
}