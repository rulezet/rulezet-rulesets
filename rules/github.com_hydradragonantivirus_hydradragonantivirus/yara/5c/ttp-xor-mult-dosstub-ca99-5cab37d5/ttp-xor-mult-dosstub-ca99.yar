rule TTP_XOR_MULT_DOSStub_ca99 {
  strings:
    $key_ca99 = { 9e f1 [2] ea e9 [2] ad eb [2] ea fa [2] a4 f6 [2] a8 fc [2] bf f7 [2] a4 b9 [2] 99 }

  condition:
    any of them
}