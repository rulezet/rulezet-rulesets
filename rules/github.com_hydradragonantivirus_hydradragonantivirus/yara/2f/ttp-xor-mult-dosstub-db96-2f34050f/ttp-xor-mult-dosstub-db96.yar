rule TTP_XOR_MULT_DOSStub_db96 {
  strings:
    $key_db96 = { 8f fe [2] fb e6 [2] bc e4 [2] fb f5 [2] b5 f9 [2] b9 f3 [2] ae f8 [2] b5 b6 [2] 88 }

  condition:
    any of them
}