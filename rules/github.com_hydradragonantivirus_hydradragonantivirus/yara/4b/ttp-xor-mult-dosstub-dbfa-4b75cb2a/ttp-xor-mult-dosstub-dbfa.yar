rule TTP_XOR_MULT_DOSStub_dbfa {
  strings:
    $key_dbfa = { 8f 92 [2] fb 8a [2] bc 88 [2] fb 99 [2] b5 95 [2] b9 9f [2] ae 94 [2] b5 da [2] 88 }

  condition:
    any of them
}