rule TTP_XOR_MULT_DOSStub_1b94 {
  strings:
    $key_1b94 = { 4f fc [2] 3b e4 [2] 7c e6 [2] 3b f7 [2] 75 fb [2] 79 f1 [2] 6e fa [2] 75 b4 [2] 48 }

  condition:
    any of them
}