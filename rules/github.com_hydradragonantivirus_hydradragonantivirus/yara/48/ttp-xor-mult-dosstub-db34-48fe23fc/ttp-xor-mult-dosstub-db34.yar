rule TTP_XOR_MULT_DOSStub_db34 {
  strings:
    $key_db34 = { 8f 5c [2] fb 44 [2] bc 46 [2] fb 57 [2] b5 5b [2] b9 51 [2] ae 5a [2] b5 14 [2] 88 }

  condition:
    any of them
}