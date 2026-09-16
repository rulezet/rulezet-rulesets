rule TTP_XOR_MULT_DOSStub_db39 {
  strings:
    $key_db39 = { 8f 51 [2] fb 49 [2] bc 4b [2] fb 5a [2] b5 56 [2] b9 5c [2] ae 57 [2] b5 19 [2] 88 }

  condition:
    any of them
}