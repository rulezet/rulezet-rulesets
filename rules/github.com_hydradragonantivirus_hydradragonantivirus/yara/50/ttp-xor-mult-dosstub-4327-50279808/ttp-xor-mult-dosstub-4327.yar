rule TTP_XOR_MULT_DOSStub_4327 {
  strings:
    $key_4327 = { 17 4f [2] 63 57 [2] 24 55 [2] 63 44 [2] 2d 48 [2] 21 42 [2] 36 49 [2] 2d 07 [2] 10 }

  condition:
    any of them
}