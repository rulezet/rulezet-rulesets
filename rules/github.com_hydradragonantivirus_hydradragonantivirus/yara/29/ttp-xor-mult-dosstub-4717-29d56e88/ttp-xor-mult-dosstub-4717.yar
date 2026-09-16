rule TTP_XOR_MULT_DOSStub_4717 {
  strings:
    $key_4717 = { 13 7f [2] 67 67 [2] 20 65 [2] 67 74 [2] 29 78 [2] 25 72 [2] 32 79 [2] 29 37 [2] 14 }

  condition:
    any of them
}