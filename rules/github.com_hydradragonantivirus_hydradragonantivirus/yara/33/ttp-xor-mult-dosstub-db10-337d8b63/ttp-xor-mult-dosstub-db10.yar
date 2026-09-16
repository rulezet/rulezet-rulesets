rule TTP_XOR_MULT_DOSStub_db10 {
  strings:
    $key_db10 = { 8f 78 [2] fb 60 [2] bc 62 [2] fb 73 [2] b5 7f [2] b9 75 [2] ae 7e [2] b5 30 [2] 88 }

  condition:
    any of them
}