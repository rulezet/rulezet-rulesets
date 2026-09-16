rule TTP_XOR_MULT_DOSStub_4635 {
  strings:
    $key_4635 = { 12 5d [2] 66 45 [2] 21 47 [2] 66 56 [2] 28 5a [2] 24 50 [2] 33 5b [2] 28 15 [2] 15 }

  condition:
    any of them
}