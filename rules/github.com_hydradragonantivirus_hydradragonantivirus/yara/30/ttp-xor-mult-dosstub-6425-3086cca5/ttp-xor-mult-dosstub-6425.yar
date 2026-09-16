rule TTP_XOR_MULT_DOSStub_6425 {
  strings:
    $key_6425 = { 30 4d [2] 44 55 [2] 03 57 [2] 44 46 [2] 0a 4a [2] 06 40 [2] 11 4b [2] 0a 05 [2] 37 }

  condition:
    any of them
}