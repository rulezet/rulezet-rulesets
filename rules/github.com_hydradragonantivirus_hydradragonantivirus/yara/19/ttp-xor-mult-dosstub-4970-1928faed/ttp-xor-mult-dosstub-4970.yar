rule TTP_XOR_MULT_DOSStub_4970 {
  strings:
    $key_4970 = { 1d 18 [2] 69 00 [2] 2e 02 [2] 69 13 [2] 27 1f [2] 2b 15 [2] 3c 1e [2] 27 50 [2] 1a }

  condition:
    any of them
}