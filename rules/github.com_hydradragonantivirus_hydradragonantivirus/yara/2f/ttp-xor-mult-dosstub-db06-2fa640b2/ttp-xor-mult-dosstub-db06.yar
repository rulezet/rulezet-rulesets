rule TTP_XOR_MULT_DOSStub_db06 {
  strings:
    $key_db06 = { 8f 6e [2] fb 76 [2] bc 74 [2] fb 65 [2] b5 69 [2] b9 63 [2] ae 68 [2] b5 26 [2] 88 }

  condition:
    any of them
}