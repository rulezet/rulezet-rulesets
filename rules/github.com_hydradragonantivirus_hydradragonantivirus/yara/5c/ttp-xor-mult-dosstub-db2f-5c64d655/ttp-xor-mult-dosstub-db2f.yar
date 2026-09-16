rule TTP_XOR_MULT_DOSStub_db2f {
  strings:
    $key_db2f = { 8f 47 [2] fb 5f [2] bc 5d [2] fb 4c [2] b5 40 [2] b9 4a [2] ae 41 [2] b5 0f [2] 88 }

  condition:
    any of them
}