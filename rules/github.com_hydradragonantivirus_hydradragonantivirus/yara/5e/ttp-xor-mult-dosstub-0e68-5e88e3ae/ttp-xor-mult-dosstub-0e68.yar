rule TTP_XOR_MULT_DOSStub_0e68 {
  strings:
    $key_0e68 = { 5a 00 [2] 2e 18 [2] 69 1a [2] 2e 0b [2] 60 07 [2] 6c 0d [2] 7b 06 [2] 60 48 [2] 5d }

  condition:
    any of them
}