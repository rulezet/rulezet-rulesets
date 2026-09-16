rule TTP_XOR_MULT_DOSStub_5b54 {
  strings:
    $key_5b54 = { 0f 3c [2] 7b 24 [2] 3c 26 [2] 7b 37 [2] 35 3b [2] 39 31 [2] 2e 3a [2] 35 74 [2] 08 }

  condition:
    any of them
}