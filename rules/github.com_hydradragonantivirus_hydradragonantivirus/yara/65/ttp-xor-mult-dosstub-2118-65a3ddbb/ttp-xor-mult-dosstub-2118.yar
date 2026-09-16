rule TTP_XOR_MULT_DOSStub_2118 {
  strings:
    $key_2118 = { 75 70 [2] 01 68 [2] 46 6a [2] 01 7b [2] 4f 77 [2] 43 7d [2] 54 76 [2] 4f 38 [2] 72 }

  condition:
    any of them
}