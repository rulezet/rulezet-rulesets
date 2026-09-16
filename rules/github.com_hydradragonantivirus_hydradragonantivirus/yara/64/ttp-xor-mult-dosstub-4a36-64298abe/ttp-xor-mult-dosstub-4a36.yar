rule TTP_XOR_MULT_DOSStub_4a36 {
  strings:
    $key_4a36 = { 1e 5e [2] 6a 46 [2] 2d 44 [2] 6a 55 [2] 24 59 [2] 28 53 [2] 3f 58 [2] 24 16 [2] 19 }

  condition:
    any of them
}