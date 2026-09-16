rule TTP_XOR_MULT_DOSStub_3525 {
  strings:
    $key_3525 = { 61 4d [2] 15 55 [2] 52 57 [2] 15 46 [2] 5b 4a [2] 57 40 [2] 40 4b [2] 5b 05 [2] 66 }

  condition:
    any of them
}