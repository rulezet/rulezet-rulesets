rule TTP_XOR_MULT_DOSStub_dbf9 {
  strings:
    $key_dbf9 = { 8f 91 [2] fb 89 [2] bc 8b [2] fb 9a [2] b5 96 [2] b9 9c [2] ae 97 [2] b5 d9 [2] 88 }

  condition:
    any of them
}