rule TTP_XOR_MULT_DOSStub_7612 {
  strings:
    $key_7612 = { 22 7a [2] 56 62 [2] 11 60 [2] 56 71 [2] 18 7d [2] 14 77 [2] 03 7c [2] 18 32 [2] 25 }

  condition:
    any of them
}