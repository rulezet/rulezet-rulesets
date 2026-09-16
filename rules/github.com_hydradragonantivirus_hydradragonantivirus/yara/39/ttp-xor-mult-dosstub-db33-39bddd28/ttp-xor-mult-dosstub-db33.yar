rule TTP_XOR_MULT_DOSStub_db33 {
  strings:
    $key_db33 = { 8f 5b [2] fb 43 [2] bc 41 [2] fb 50 [2] b5 5c [2] b9 56 [2] ae 5d [2] b5 13 [2] 88 }

  condition:
    any of them
}