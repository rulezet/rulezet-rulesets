rule TTP_XOR_MULT_DOSStub_4c99 {
  strings:
    $key_4c99 = { 18 f1 [2] 6c e9 [2] 2b eb [2] 6c fa [2] 22 f6 [2] 2e fc [2] 39 f7 [2] 22 b9 [2] 1f }

  condition:
    any of them
}