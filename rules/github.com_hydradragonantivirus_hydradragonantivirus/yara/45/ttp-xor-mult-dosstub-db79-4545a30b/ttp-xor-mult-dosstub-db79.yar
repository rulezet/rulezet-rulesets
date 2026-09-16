rule TTP_XOR_MULT_DOSStub_db79 {
  strings:
    $key_db79 = { 8f 11 [2] fb 09 [2] bc 0b [2] fb 1a [2] b5 16 [2] b9 1c [2] ae 17 [2] b5 59 [2] 88 }

  condition:
    any of them
}