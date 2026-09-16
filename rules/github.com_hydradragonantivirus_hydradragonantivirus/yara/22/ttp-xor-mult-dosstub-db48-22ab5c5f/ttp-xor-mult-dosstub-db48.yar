rule TTP_XOR_MULT_DOSStub_db48 {
  strings:
    $key_db48 = { 8f 20 [2] fb 38 [2] bc 3a [2] fb 2b [2] b5 27 [2] b9 2d [2] ae 26 [2] b5 68 [2] 88 }

  condition:
    any of them
}