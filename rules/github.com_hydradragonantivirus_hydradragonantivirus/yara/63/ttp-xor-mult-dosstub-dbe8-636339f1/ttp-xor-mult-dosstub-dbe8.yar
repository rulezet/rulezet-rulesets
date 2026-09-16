rule TTP_XOR_MULT_DOSStub_dbe8 {
  strings:
    $key_dbe8 = { 8f 80 [2] fb 98 [2] bc 9a [2] fb 8b [2] b5 87 [2] b9 8d [2] ae 86 [2] b5 c8 [2] 88 }

  condition:
    any of them
}