rule TTP_XOR_MULT_DOSStub_4636 {
  strings:
    $key_4636 = { 12 5e [2] 66 46 [2] 21 44 [2] 66 55 [2] 28 59 [2] 24 53 [2] 33 58 [2] 28 16 [2] 15 }

  condition:
    any of them
}