rule TTP_XOR_MULT_DOSStub_ae99 {
  strings:
    $key_ae99 = { fa f1 [2] 8e e9 [2] c9 eb [2] 8e fa [2] c0 f6 [2] cc fc [2] db f7 [2] c0 b9 [2] fd }

  condition:
    any of them
}