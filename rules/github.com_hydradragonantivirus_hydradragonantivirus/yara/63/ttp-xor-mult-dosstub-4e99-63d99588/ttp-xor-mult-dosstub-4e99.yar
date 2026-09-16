rule TTP_XOR_MULT_DOSStub_4e99 {
  strings:
    $key_4e99 = { 1a f1 [2] 6e e9 [2] 29 eb [2] 6e fa [2] 20 f6 [2] 2c fc [2] 3b f7 [2] 20 b9 [2] 1d }

  condition:
    any of them
}