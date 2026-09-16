rule TTP_XOR_MULT_DOSStub_de99 {
  strings:
    $key_de99 = { 8a f1 [2] fe e9 [2] b9 eb [2] fe fa [2] b0 f6 [2] bc fc [2] ab f7 [2] b0 b9 [2] 8d }

  condition:
    any of them
}