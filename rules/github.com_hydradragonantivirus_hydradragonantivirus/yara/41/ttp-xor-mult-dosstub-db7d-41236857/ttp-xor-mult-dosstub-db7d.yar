rule TTP_XOR_MULT_DOSStub_db7d {
  strings:
    $key_db7d = { 8f 15 [2] fb 0d [2] bc 0f [2] fb 1e [2] b5 12 [2] b9 18 [2] ae 13 [2] b5 5d [2] 88 }

  condition:
    any of them
}