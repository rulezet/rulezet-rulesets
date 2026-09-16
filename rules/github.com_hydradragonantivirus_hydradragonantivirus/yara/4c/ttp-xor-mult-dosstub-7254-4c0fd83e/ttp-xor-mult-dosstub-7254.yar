rule TTP_XOR_MULT_DOSStub_7254 {
  strings:
    $key_7254 = { 26 3c [2] 52 24 [2] 15 26 [2] 52 37 [2] 1c 3b [2] 10 31 [2] 07 3a [2] 1c 74 [2] 21 }

  condition:
    any of them
}