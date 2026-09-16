rule TTP_XOR_MULT_DOSStub_4956 {
  strings:
    $key_4956 = { 1d 3e [2] 69 26 [2] 2e 24 [2] 69 35 [2] 27 39 [2] 2b 33 [2] 3c 38 [2] 27 76 [2] 1a }

  condition:
    any of them
}