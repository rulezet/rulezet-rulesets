rule TTP_XOR_MULT_DOSStub_4712 {
  strings:
    $key_4712 = { 13 7a [2] 67 62 [2] 20 60 [2] 67 71 [2] 29 7d [2] 25 77 [2] 32 7c [2] 29 32 [2] 14 }

  condition:
    any of them
}