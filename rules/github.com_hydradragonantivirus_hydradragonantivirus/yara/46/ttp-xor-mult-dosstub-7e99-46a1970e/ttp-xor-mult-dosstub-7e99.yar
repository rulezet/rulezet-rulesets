rule TTP_XOR_MULT_DOSStub_7e99 {
  strings:
    $key_7e99 = { 2a f1 [2] 5e e9 [2] 19 eb [2] 5e fa [2] 10 f6 [2] 1c fc [2] 0b f7 [2] 10 b9 [2] 2d }

  condition:
    any of them
}