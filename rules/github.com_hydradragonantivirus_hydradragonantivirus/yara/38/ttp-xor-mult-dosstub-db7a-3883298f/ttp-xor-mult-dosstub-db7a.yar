rule TTP_XOR_MULT_DOSStub_db7a {
  strings:
    $key_db7a = { 8f 12 [2] fb 0a [2] bc 08 [2] fb 19 [2] b5 15 [2] b9 1f [2] ae 14 [2] b5 5a [2] 88 }

  condition:
    any of them
}