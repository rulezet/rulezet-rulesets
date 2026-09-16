rule TTP_XOR_MULT_DOSStub_0e65 {
  strings:
    $key_0e65 = { 5a 0d [2] 2e 15 [2] 69 17 [2] 2e 06 [2] 60 0a [2] 6c 00 [2] 7b 0b [2] 60 45 [2] 5d }

  condition:
    any of them
}