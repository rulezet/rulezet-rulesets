rule TTP_XOR_MULT_DOSStub_3259 {
  strings:
    $key_3259 = { 66 31 [2] 12 29 [2] 55 2b [2] 12 3a [2] 5c 36 [2] 50 3c [2] 47 37 [2] 5c 79 [2] 61 }

  condition:
    any of them
}