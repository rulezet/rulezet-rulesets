rule TTP_XOR_MULT_DOSStub_db59 {
  strings:
    $key_db59 = { 8f 31 [2] fb 29 [2] bc 2b [2] fb 3a [2] b5 36 [2] b9 3c [2] ae 37 [2] b5 79 [2] 88 }

  condition:
    any of them
}