rule TTP_XOR_MULT_DOSStub_4612 {
  strings:
    $key_4612 = { 12 7a [2] 66 62 [2] 21 60 [2] 66 71 [2] 28 7d [2] 24 77 [2] 33 7c [2] 28 32 [2] 15 }

  condition:
    any of them
}