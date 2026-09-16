rule TTP_XOR_MULT_DOSStub_db37 {
  strings:
    $key_db37 = { 8f 5f [2] fb 47 [2] bc 45 [2] fb 54 [2] b5 58 [2] b9 52 [2] ae 59 [2] b5 17 [2] 88 }

  condition:
    any of them
}