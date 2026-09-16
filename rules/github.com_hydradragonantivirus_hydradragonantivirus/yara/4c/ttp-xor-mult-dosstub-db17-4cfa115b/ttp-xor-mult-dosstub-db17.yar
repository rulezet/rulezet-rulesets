rule TTP_XOR_MULT_DOSStub_db17 {
  strings:
    $key_db17 = { 8f 7f [2] fb 67 [2] bc 65 [2] fb 74 [2] b5 78 [2] b9 72 [2] ae 79 [2] b5 37 [2] 88 }

  condition:
    any of them
}