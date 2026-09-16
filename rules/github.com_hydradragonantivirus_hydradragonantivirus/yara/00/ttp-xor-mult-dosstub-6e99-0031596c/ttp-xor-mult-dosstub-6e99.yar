rule TTP_XOR_MULT_DOSStub_6e99 {
  strings:
    $key_6e99 = { 3a f1 [2] 4e e9 [2] 09 eb [2] 4e fa [2] 00 f6 [2] 0c fc [2] 1b f7 [2] 00 b9 [2] 3d }

  condition:
    any of them
}