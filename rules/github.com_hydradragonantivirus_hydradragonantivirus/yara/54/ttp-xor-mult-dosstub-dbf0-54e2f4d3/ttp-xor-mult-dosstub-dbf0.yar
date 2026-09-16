rule TTP_XOR_MULT_DOSStub_dbf0 {
  strings:
    $key_dbf0 = { 8f 98 [2] fb 80 [2] bc 82 [2] fb 93 [2] b5 9f [2] b9 95 [2] ae 9e [2] b5 d0 [2] 88 }

  condition:
    any of them
}