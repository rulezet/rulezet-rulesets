rule TTP_XOR_MULT_DOSStub_4947 {
  strings:
    $key_4947 = { 1d 2f [2] 69 37 [2] 2e 35 [2] 69 24 [2] 27 28 [2] 2b 22 [2] 3c 29 [2] 27 67 [2] 1a }

  condition:
    any of them
}