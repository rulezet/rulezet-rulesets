rule TTP_XOR_MULT_DOSStub_db87 {
  strings:
    $key_db87 = { 8f ef [2] fb f7 [2] bc f5 [2] fb e4 [2] b5 e8 [2] b9 e2 [2] ae e9 [2] b5 a7 [2] 88 }

  condition:
    any of them
}