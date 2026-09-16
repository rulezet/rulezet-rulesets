rule TTP_XOR_MULT_DOSStub_5225 {
  strings:
    $key_5225 = { 06 4d [2] 72 55 [2] 35 57 [2] 72 46 [2] 3c 4a [2] 30 40 [2] 27 4b [2] 3c 05 [2] 01 }

  condition:
    any of them
}