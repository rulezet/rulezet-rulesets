rule TTP_XOR_MULT_DOSStub_db3a {
  strings:
    $key_db3a = { 8f 52 [2] fb 4a [2] bc 48 [2] fb 59 [2] b5 55 [2] b9 5f [2] ae 54 [2] b5 1a [2] 88 }

  condition:
    any of them
}