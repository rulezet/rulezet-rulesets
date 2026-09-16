rule TTP_XOR_MULT_DOSStub_6519 {
  strings:
    $key_6519 = { 31 71 [2] 45 69 [2] 02 6b [2] 45 7a [2] 0b 76 [2] 07 7c [2] 10 77 [2] 0b 39 [2] 36 }

  condition:
    any of them
}