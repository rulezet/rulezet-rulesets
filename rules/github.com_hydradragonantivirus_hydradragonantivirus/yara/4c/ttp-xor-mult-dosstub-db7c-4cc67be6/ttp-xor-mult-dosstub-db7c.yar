rule TTP_XOR_MULT_DOSStub_db7c {
  strings:
    $key_db7c = { 8f 14 [2] fb 0c [2] bc 0e [2] fb 1f [2] b5 13 [2] b9 19 [2] ae 12 [2] b5 5c [2] 88 }

  condition:
    any of them
}