rule TTP_XOR_MULT_DOSStub_db11 {
  strings:
    $key_db11 = { 8f 79 [2] fb 61 [2] bc 63 [2] fb 72 [2] b5 7e [2] b9 74 [2] ae 7f [2] b5 31 [2] 88 }

  condition:
    any of them
}