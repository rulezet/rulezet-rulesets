rule TTP_XOR_MULT_DOSStub_db56 {
  strings:
    $key_db56 = { 8f 3e [2] fb 26 [2] bc 24 [2] fb 35 [2] b5 39 [2] b9 33 [2] ae 38 [2] b5 76 [2] 88 }

  condition:
    any of them
}