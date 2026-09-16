rule TTP_XOR_MULT_DOSStub_db19 {
  strings:
    $key_db19 = { 8f 71 [2] fb 69 [2] bc 6b [2] fb 7a [2] b5 76 [2] b9 7c [2] ae 77 [2] b5 39 [2] 88 }

  condition:
    any of them
}