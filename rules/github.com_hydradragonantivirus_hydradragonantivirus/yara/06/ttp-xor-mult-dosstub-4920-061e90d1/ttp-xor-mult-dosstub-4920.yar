rule TTP_XOR_MULT_DOSStub_4920 {
  strings:
    $key_4920 = { 1d 48 [2] 69 50 [2] 2e 52 [2] 69 43 [2] 27 4f [2] 2b 45 [2] 3c 4e [2] 27 00 [2] 1a }

  condition:
    any of them
}