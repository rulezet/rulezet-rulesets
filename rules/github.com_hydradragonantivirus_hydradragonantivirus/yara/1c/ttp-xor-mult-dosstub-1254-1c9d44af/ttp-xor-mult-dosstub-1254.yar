rule TTP_XOR_MULT_DOSStub_1254 {
  strings:
    $key_1254 = { 46 3c [2] 32 24 [2] 75 26 [2] 32 37 [2] 7c 3b [2] 70 31 [2] 67 3a [2] 7c 74 [2] 41 }

  condition:
    any of them
}