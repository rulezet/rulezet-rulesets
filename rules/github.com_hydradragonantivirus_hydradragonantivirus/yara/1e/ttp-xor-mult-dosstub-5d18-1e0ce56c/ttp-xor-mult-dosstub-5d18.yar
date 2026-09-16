rule TTP_XOR_MULT_DOSStub_5d18 {
  strings:
    $key_5d18 = { 09 70 [2] 7d 68 [2] 3a 6a [2] 7d 7b [2] 33 77 [2] 3f 7d [2] 28 76 [2] 33 38 [2] 0e }

  condition:
    any of them
}