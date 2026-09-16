rule TTP_XOR_MULT_DOSStub_3b94 {
  strings:
    $key_3b94 = { 6f fc [2] 1b e4 [2] 5c e6 [2] 1b f7 [2] 55 fb [2] 59 f1 [2] 4e fa [2] 55 b4 [2] 68 }

  condition:
    any of them
}