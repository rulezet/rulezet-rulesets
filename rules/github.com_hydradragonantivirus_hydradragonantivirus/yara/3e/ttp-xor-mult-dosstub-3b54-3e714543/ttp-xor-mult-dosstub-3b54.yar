rule TTP_XOR_MULT_DOSStub_3b54 {
  strings:
    $key_3b54 = { 6f 3c [2] 1b 24 [2] 5c 26 [2] 1b 37 [2] 55 3b [2] 59 31 [2] 4e 3a [2] 55 74 [2] 68 }

  condition:
    any of them
}