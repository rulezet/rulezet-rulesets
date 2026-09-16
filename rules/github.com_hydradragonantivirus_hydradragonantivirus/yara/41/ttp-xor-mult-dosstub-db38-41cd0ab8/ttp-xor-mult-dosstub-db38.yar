rule TTP_XOR_MULT_DOSStub_db38 {
  strings:
    $key_db38 = { 8f 50 [2] fb 48 [2] bc 4a [2] fb 5b [2] b5 57 [2] b9 5d [2] ae 56 [2] b5 18 [2] 88 }

  condition:
    any of them
}