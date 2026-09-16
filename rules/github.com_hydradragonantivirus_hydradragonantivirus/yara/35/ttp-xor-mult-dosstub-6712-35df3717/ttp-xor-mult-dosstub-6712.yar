rule TTP_XOR_MULT_DOSStub_6712 {
  strings:
    $key_6712 = { 33 7a [2] 47 62 [2] 00 60 [2] 47 71 [2] 09 7d [2] 05 77 [2] 12 7c [2] 09 32 [2] 34 }

  condition:
    any of them
}