rule TTP_XOR_MULT_DOSStub_db72 {
  strings:
    $key_db72 = { 8f 1a [2] fb 02 [2] bc 00 [2] fb 11 [2] b5 1d [2] b9 17 [2] ae 1c [2] b5 52 [2] 88 }

  condition:
    any of them
}