rule TTP_XOR_MULT_DOSStub_3947 {
  strings:
    $key_3947 = { 6d 2f [2] 19 37 [2] 5e 35 [2] 19 24 [2] 57 28 [2] 5b 22 [2] 4c 29 [2] 57 67 [2] 6a }

  condition:
    any of them
}