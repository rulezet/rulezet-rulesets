rule TTP_XOR_MULT_DOSStub_5d14 {
  strings:
    $key_5d14 = { 09 7c [2] 7d 64 [2] 3a 66 [2] 7d 77 [2] 33 7b [2] 3f 71 [2] 28 7a [2] 33 34 [2] 0e }

  condition:
    any of them
}