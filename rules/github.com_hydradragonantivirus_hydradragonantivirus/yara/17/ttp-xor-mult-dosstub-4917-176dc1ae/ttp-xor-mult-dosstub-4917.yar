rule TTP_XOR_MULT_DOSStub_4917 {
  strings:
    $key_4917 = { 1d 7f [2] 69 67 [2] 2e 65 [2] 69 74 [2] 27 78 [2] 2b 72 [2] 3c 79 [2] 27 37 [2] 1a }

  condition:
    any of them
}