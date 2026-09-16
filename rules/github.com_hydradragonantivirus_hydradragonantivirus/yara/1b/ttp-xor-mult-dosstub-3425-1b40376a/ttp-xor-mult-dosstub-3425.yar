rule TTP_XOR_MULT_DOSStub_3425 {
  strings:
    $key_3425 = { 60 4d [2] 14 55 [2] 53 57 [2] 14 46 [2] 5a 4a [2] 56 40 [2] 41 4b [2] 5a 05 [2] 67 }

  condition:
    any of them
}