rule TTP_XOR_MULT_DOSStub_db52 {
  strings:
    $key_db52 = { 8f 3a [2] fb 22 [2] bc 20 [2] fb 31 [2] b5 3d [2] b9 37 [2] ae 3c [2] b5 72 [2] 88 }

  condition:
    any of them
}