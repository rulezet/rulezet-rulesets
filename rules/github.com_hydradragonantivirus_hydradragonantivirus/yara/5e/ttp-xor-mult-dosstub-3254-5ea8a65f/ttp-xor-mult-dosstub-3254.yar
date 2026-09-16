rule TTP_XOR_MULT_DOSStub_3254 {
  strings:
    $key_3254 = { 66 3c [2] 12 24 [2] 55 26 [2] 12 37 [2] 5c 3b [2] 50 31 [2] 47 3a [2] 5c 74 [2] 61 }

  condition:
    any of them
}