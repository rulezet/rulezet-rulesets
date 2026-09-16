rule TTP_XOR_MULT_DOSStub_2559 {
  strings:
    $key_2559 = { 71 31 [2] 05 29 [2] 42 2b [2] 05 3a [2] 4b 36 [2] 47 3c [2] 50 37 [2] 4b 79 [2] 76 }

  condition:
    any of them
}