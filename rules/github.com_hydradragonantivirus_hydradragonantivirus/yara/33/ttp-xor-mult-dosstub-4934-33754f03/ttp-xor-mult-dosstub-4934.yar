rule TTP_XOR_MULT_DOSStub_4934 {
  strings:
    $key_4934 = { 1d 5c [2] 69 44 [2] 2e 46 [2] 69 57 [2] 27 5b [2] 2b 51 [2] 3c 5a [2] 27 14 [2] 1a }

  condition:
    any of them
}