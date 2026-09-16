rule TTP_XOR_MULT_DOSStub_4937 {
  strings:
    $key_4937 = { 1d 5f [2] 69 47 [2] 2e 45 [2] 69 54 [2] 27 58 [2] 2b 52 [2] 3c 59 [2] 27 17 [2] 1a }

  condition:
    any of them
}