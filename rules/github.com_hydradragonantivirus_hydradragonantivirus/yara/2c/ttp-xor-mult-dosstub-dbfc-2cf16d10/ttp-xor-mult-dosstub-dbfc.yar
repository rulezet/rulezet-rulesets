rule TTP_XOR_MULT_DOSStub_dbfc {
  strings:
    $key_dbfc = { 8f 94 [2] fb 8c [2] bc 8e [2] fb 9f [2] b5 93 [2] b9 99 [2] ae 92 [2] b5 dc [2] 88 }

  condition:
    any of them
}