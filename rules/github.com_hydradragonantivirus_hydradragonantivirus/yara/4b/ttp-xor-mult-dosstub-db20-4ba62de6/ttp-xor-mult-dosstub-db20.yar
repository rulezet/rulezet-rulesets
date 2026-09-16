rule TTP_XOR_MULT_DOSStub_db20 {
  strings:
    $key_db20 = { 8f 48 [2] fb 50 [2] bc 52 [2] fb 43 [2] b5 4f [2] b9 45 [2] ae 4e [2] b5 00 [2] 88 }

  condition:
    any of them
}