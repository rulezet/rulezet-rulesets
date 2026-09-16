rule TTP_XOR_MULT_DOSStub_db63 {
  strings:
    $key_db63 = { 8f 0b [2] fb 13 [2] bc 11 [2] fb 00 [2] b5 0c [2] b9 06 [2] ae 0d [2] b5 43 [2] 88 }

  condition:
    any of them
}