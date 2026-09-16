rule TTP_XOR_MULT_DOSStub_4714 {
  strings:
    $key_4714 = { 13 7c [2] 67 64 [2] 20 66 [2] 67 77 [2] 29 7b [2] 25 71 [2] 32 7a [2] 29 34 [2] 14 }

  condition:
    any of them
}