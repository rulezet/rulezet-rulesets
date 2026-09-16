rule TTP_XOR_MULT_DOSStub_0a59 {
  strings:
    $key_0a59 = { 5e 31 [2] 2a 29 [2] 6d 2b [2] 2a 3a [2] 64 36 [2] 68 3c [2] 7f 37 [2] 64 79 [2] 59 }

  condition:
    any of them
}