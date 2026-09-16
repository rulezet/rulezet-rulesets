rule TTP_XOR_MULT_DOSStub_db25 {
  strings:
    $key_db25 = { 8f 4d [2] fb 55 [2] bc 57 [2] fb 46 [2] b5 4a [2] b9 40 [2] ae 4b [2] b5 05 [2] 88 }

  condition:
    any of them
}