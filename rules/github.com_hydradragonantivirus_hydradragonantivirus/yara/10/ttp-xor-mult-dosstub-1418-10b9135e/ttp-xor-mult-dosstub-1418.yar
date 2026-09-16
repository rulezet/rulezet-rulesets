rule TTP_XOR_MULT_DOSStub_1418 {
  strings:
    $key_1418 = { 40 70 [2] 34 68 [2] 73 6a [2] 34 7b [2] 7a 77 [2] 76 7d [2] 61 76 [2] 7a 38 [2] 47 }

  condition:
    any of them
}