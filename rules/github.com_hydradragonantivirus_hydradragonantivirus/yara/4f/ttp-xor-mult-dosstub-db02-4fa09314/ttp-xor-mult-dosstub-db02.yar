rule TTP_XOR_MULT_DOSStub_db02 {
  strings:
    $key_db02 = { 8f 6a [2] fb 72 [2] bc 70 [2] fb 61 [2] b5 6d [2] b9 67 [2] ae 6c [2] b5 22 [2] 88 }

  condition:
    any of them
}