rule TTP_XOR_MULT_DOSStub_4018 {
  strings:
    $key_4018 = { 14 70 [2] 60 68 [2] 27 6a [2] 60 7b [2] 2e 77 [2] 22 7d [2] 35 76 [2] 2e 38 [2] 13 }

  condition:
    any of them
}