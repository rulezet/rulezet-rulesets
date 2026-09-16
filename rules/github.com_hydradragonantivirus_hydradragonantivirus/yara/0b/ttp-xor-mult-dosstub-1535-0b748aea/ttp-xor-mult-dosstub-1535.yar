rule TTP_XOR_MULT_DOSStub_1535 {
  strings:
    $key_1535 = { 41 5d [2] 35 45 [2] 72 47 [2] 35 56 [2] 7b 5a [2] 77 50 [2] 60 5b [2] 7b 15 [2] 46 }

  condition:
    any of them
}