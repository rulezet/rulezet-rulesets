rule TTP_XOR_MULT_DOSStub_4943 {
  strings:
    $key_4943 = { 1d 2b [2] 69 33 [2] 2e 31 [2] 69 20 [2] 27 2c [2] 2b 26 [2] 3c 2d [2] 27 63 [2] 1a }

  condition:
    any of them
}