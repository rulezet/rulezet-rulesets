rule TTP_XOR_MULT_DOSStub_db1a {
  strings:
    $key_db1a = { 8f 72 [2] fb 6a [2] bc 68 [2] fb 79 [2] b5 75 [2] b9 7f [2] ae 74 [2] b5 3a [2] 88 }

  condition:
    any of them
}