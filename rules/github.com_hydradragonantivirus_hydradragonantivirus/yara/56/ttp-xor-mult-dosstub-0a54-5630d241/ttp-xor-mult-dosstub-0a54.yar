rule TTP_XOR_MULT_DOSStub_0a54 {
  strings:
    $key_0a54 = { 5e 3c [2] 2a 24 [2] 6d 26 [2] 2a 37 [2] 64 3b [2] 68 31 [2] 7f 3a [2] 64 74 [2] 59 }

  condition:
    any of them
}