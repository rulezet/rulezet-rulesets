rule TTP_XOR_MULT_DOSStub_1a18 {
  strings:
    $key_1a18 = { 4e 70 [2] 3a 68 [2] 7d 6a [2] 3a 7b [2] 74 77 [2] 78 7d [2] 6f 76 [2] 74 38 [2] 49 }

  condition:
    any of them
}