rule TTP_XOR_MULT_DOSStub_6947 {
  strings:
    $key_6947 = { 3d 2f [2] 49 37 [2] 0e 35 [2] 49 24 [2] 07 28 [2] 0b 22 [2] 1c 29 [2] 07 67 [2] 3a }

  condition:
    any of them
}