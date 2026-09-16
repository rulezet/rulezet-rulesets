rule TTP_XOR_MULT_DOSStub_db65 {
  strings:
    $key_db65 = { 8f 0d [2] fb 15 [2] bc 17 [2] fb 06 [2] b5 0a [2] b9 00 [2] ae 0b [2] b5 45 [2] 88 }

  condition:
    any of them
}