rule TTP_XOR_MULT_DOSStub_43e6 {
  strings:
    $key_43e6 = { 17 8e [2] 63 96 [2] 24 94 [2] 63 85 [2] 2d 89 [2] 21 83 [2] 36 88 [2] 2d c6 [2] 10 }

  condition:
    any of them
}