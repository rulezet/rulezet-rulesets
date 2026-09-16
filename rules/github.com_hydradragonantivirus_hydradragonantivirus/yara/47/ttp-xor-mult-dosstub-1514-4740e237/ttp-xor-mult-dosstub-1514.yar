rule TTP_XOR_MULT_DOSStub_1514 {
  strings:
    $key_1514 = { 41 7c [2] 35 64 [2] 72 66 [2] 35 77 [2] 7b 7b [2] 77 71 [2] 60 7a [2] 7b 34 [2] 46 }

  condition:
    any of them
}