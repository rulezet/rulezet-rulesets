rule TTP_XOR_MULT_DOSStub_1718 {
  strings:
    $key_1718 = { 43 70 [2] 37 68 [2] 70 6a [2] 37 7b [2] 79 77 [2] 75 7d [2] 62 76 [2] 79 38 [2] 44 }

  condition:
    any of them
}