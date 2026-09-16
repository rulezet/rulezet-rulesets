rule TTP_XOR_MULT_DOSStub_4915 {
  strings:
    $key_4915 = { 1d 7d [2] 69 65 [2] 2e 67 [2] 69 76 [2] 27 7a [2] 2b 70 [2] 3c 7b [2] 27 35 [2] 1a }

  condition:
    any of them
}