rule TTP_XOR_MULT_DOSStub_1425 {
  strings:
    $key_1425 = { 40 4d [2] 34 55 [2] 73 57 [2] 34 46 [2] 7a 4a [2] 76 40 [2] 61 4b [2] 7a 05 [2] 47 }

  condition:
    any of them
}