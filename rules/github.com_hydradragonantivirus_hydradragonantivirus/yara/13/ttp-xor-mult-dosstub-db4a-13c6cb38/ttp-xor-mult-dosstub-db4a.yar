rule TTP_XOR_MULT_DOSStub_db4a {
  strings:
    $key_db4a = { 8f 22 [2] fb 3a [2] bc 38 [2] fb 29 [2] b5 25 [2] b9 2f [2] ae 24 [2] b5 6a [2] 88 }

  condition:
    any of them
}