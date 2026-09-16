rule TTP_XOR_MULT_DOSStub_db40 {
  strings:
    $key_db40 = { 8f 28 [2] fb 30 [2] bc 32 [2] fb 23 [2] b5 2f [2] b9 25 [2] ae 2e [2] b5 60 [2] 88 }

  condition:
    any of them
}