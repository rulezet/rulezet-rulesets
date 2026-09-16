rule TTP_XOR_MULT_DOSStub_db67 {
  strings:
    $key_db67 = { 8f 0f [2] fb 17 [2] bc 15 [2] fb 04 [2] b5 08 [2] b9 02 [2] ae 09 [2] b5 47 [2] 88 }

  condition:
    any of them
}