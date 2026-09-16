rule TTP_XOR_MULT_DOSStub_db28 {
  strings:
    $key_db28 = { 8f 40 [2] fb 58 [2] bc 5a [2] fb 4b [2] b5 47 [2] b9 4d [2] ae 46 [2] b5 08 [2] 88 }

  condition:
    any of them
}