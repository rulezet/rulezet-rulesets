rule TTP_XOR_MULT_DOSStub_db44 {
  strings:
    $key_db44 = { 8f 2c [2] fb 34 [2] bc 36 [2] fb 27 [2] b5 2b [2] b9 21 [2] ae 2a [2] b5 64 [2] 88 }

  condition:
    any of them
}