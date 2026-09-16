rule TTP_XOR_MULT_DOSStub_db9e {
  strings:
    $key_db9e = { 8f f6 [2] fb ee [2] bc ec [2] fb fd [2] b5 f1 [2] b9 fb [2] ae f0 [2] b5 be [2] 88 }

  condition:
    any of them
}