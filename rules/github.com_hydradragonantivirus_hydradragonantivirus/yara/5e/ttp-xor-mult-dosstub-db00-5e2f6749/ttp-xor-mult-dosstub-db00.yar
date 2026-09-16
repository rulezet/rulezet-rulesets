rule TTP_XOR_MULT_DOSStub_db00 {
  strings:
    $key_db00 = { 8f 68 [2] fb 70 [2] bc 72 [2] fb 63 [2] b5 6f [2] b9 65 [2] ae 6e [2] b5 20 [2] 88 }

  condition:
    any of them
}