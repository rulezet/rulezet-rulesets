rule TTP_XOR_MULT_DOSStub_db41 {
  strings:
    $key_db41 = { 8f 29 [2] fb 31 [2] bc 33 [2] fb 22 [2] b5 2e [2] b9 24 [2] ae 2f [2] b5 61 [2] 88 }

  condition:
    any of them
}