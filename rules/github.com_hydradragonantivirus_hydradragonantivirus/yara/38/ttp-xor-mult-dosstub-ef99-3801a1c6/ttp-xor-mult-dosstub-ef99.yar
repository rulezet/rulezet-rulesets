rule TTP_XOR_MULT_DOSStub_ef99 {
  strings:
    $key_ef99 = { bb f1 [2] cf e9 [2] 88 eb [2] cf fa [2] 81 f6 [2] 8d fc [2] 9a f7 [2] 81 b9 [2] bc }

  condition:
    any of them
}