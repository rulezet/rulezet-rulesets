rule TTP_XOR_MULT_DOSStub_0519 {
  strings:
    $key_0519 = { 51 71 [2] 25 69 [2] 62 6b [2] 25 7a [2] 6b 76 [2] 67 7c [2] 70 77 [2] 6b 39 [2] 56 }

  condition:
    any of them
}