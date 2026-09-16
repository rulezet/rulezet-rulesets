rule TTP_XOR_MULT_DOSStub_4321 {
  strings:
    $key_4321 = { 17 49 [2] 63 51 [2] 24 53 [2] 63 42 [2] 2d 4e [2] 21 44 [2] 36 4f [2] 2d 01 [2] 10 }

  condition:
    any of them
}