rule TTP_XOR_MULT_DOSStub_4945 {
  strings:
    $key_4945 = { 1d 2d [2] 69 35 [2] 2e 37 [2] 69 26 [2] 27 2a [2] 2b 20 [2] 3c 2b [2] 27 65 [2] 1a }

  condition:
    any of them
}