rule TTP_XOR_MULT_DOSStub_0f54 {
  strings:
    $key_0f54 = { 5b 3c [2] 2f 24 [2] 68 26 [2] 2f 37 [2] 61 3b [2] 6d 31 [2] 7a 3a [2] 61 74 [2] 5c }

  condition:
    any of them
}