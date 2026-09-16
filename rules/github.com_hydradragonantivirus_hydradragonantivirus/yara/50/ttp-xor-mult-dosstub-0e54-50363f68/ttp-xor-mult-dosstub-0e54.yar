rule TTP_XOR_MULT_DOSStub_0e54 {
  strings:
    $key_0e54 = { 5a 3c [2] 2e 24 [2] 69 26 [2] 2e 37 [2] 60 3b [2] 6c 31 [2] 7b 3a [2] 60 74 [2] 5d }

  condition:
    any of them
}