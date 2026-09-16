rule TTP_XOR_MULT_DOSStub_db36 {
  strings:
    $key_db36 = { 8f 5e [2] fb 46 [2] bc 44 [2] fb 55 [2] b5 59 [2] b9 53 [2] ae 58 [2] b5 16 [2] 88 }

  condition:
    any of them
}