rule TTP_XOR_MULT_DOSStub_db77 {
  strings:
    $key_db77 = { 8f 1f [2] fb 07 [2] bc 05 [2] fb 14 [2] b5 18 [2] b9 12 [2] ae 19 [2] b5 57 [2] 88 }

  condition:
    any of them
}