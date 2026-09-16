rule TTP_XOR_MULT_DOSStub_db66 {
  strings:
    $key_db66 = { 8f 0e [2] fb 16 [2] bc 14 [2] fb 05 [2] b5 09 [2] b9 03 [2] ae 08 [2] b5 46 [2] 88 }

  condition:
    any of them
}