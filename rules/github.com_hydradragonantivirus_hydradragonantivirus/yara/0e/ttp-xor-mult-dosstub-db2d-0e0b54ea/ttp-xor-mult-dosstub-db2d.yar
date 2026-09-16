rule TTP_XOR_MULT_DOSStub_db2d {
  strings:
    $key_db2d = { 8f 45 [2] fb 5d [2] bc 5f [2] fb 4e [2] b5 42 [2] b9 48 [2] ae 43 [2] b5 0d [2] 88 }

  condition:
    any of them
}