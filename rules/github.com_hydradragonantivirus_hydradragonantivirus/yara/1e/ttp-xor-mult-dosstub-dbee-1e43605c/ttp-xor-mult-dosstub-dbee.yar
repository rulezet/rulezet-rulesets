rule TTP_XOR_MULT_DOSStub_dbee {
  strings:
    $key_dbee = { 8f 86 [2] fb 9e [2] bc 9c [2] fb 8d [2] b5 81 [2] b9 8b [2] ae 80 [2] b5 ce [2] 88 }

  condition:
    any of them
}