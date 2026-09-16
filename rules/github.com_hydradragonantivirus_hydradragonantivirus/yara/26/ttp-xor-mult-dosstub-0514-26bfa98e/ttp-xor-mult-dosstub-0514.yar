rule TTP_XOR_MULT_DOSStub_0514 {
  strings:
    $key_0514 = { 51 7c [2] 25 64 [2] 62 66 [2] 25 77 [2] 6b 7b [2] 67 71 [2] 70 7a [2] 6b 34 [2] 56 }

  condition:
    any of them
}