rule TTP_XOR_MULT_DOSStub_dbe7 {
  strings:
    $key_dbe7 = { 8f 8f [2] fb 97 [2] bc 95 [2] fb 84 [2] b5 88 [2] b9 82 [2] ae 89 [2] b5 c7 [2] 88 }

  condition:
    any of them
}