rule TTP_XOR_MULT_DOSStub_db21 {
  strings:
    $key_db21 = { 8f 49 [2] fb 51 [2] bc 53 [2] fb 42 [2] b5 4e [2] b9 44 [2] ae 4f [2] b5 01 [2] 88 }

  condition:
    any of them
}