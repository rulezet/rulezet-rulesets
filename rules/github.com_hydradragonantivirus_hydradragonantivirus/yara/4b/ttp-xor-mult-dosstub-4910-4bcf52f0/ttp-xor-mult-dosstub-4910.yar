rule TTP_XOR_MULT_DOSStub_4910 {
  strings:
    $key_4910 = { 1d 78 [2] 69 60 [2] 2e 62 [2] 69 73 [2] 27 7f [2] 2b 75 [2] 3c 7e [2] 27 30 [2] 1a }

  condition:
    any of them
}