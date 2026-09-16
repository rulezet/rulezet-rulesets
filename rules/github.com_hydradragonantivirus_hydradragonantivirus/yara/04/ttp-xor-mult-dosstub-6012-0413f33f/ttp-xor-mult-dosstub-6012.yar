rule TTP_XOR_MULT_DOSStub_6012 {
  strings:
    $key_6012 = { 34 7a [2] 40 62 [2] 07 60 [2] 40 71 [2] 0e 7d [2] 02 77 [2] 15 7c [2] 0e 32 [2] 33 }

  condition:
    any of them
}