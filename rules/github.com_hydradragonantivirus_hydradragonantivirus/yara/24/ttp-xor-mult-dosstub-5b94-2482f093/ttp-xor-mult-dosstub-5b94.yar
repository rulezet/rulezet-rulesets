rule TTP_XOR_MULT_DOSStub_5b94 {
  strings:
    $key_5b94 = { 0f fc [2] 7b e4 [2] 3c e6 [2] 7b f7 [2] 35 fb [2] 39 f1 [2] 2e fa [2] 35 b4 [2] 08 }

  condition:
    any of them
}