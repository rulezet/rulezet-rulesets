rule TTP_XOR_MULT_DOSStub_5208 {
  strings:
    $key_5208 = { 06 60 [2] 72 78 [2] 35 7a [2] 72 6b [2] 3c 67 [2] 30 6d [2] 27 66 [2] 3c 28 [2] 01 }

  condition:
    any of them
}