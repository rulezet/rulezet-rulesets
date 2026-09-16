rule TTP_XOR_MULT_DOSStub_db50 {
  strings:
    $key_db50 = { 8f 38 [2] fb 20 [2] bc 22 [2] fb 33 [2] b5 3f [2] b9 35 [2] ae 3e [2] b5 70 [2] 88 }

  condition:
    any of them
}