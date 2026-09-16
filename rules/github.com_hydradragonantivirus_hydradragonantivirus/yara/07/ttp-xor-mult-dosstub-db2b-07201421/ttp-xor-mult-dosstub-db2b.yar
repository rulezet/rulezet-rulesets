rule TTP_XOR_MULT_DOSStub_db2b {
  strings:
    $key_db2b = { 8f 43 [2] fb 5b [2] bc 59 [2] fb 48 [2] b5 44 [2] b9 4e [2] ae 45 [2] b5 0b [2] 88 }

  condition:
    any of them
}