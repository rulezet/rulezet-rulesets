rule TTP_XOR_MULT_DOSStub_db26 {
  strings:
    $key_db26 = { 8f 4e [2] fb 56 [2] bc 54 [2] fb 45 [2] b5 49 [2] b9 43 [2] ae 48 [2] b5 06 [2] 88 }

  condition:
    any of them
}