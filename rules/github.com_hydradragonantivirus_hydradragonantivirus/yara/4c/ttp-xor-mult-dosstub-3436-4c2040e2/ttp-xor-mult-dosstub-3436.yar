rule TTP_XOR_MULT_DOSStub_3436 {
  strings:
    $key_3436 = { 60 5e [2] 14 46 [2] 53 44 [2] 14 55 [2] 5a 59 [2] 56 53 [2] 41 58 [2] 5a 16 [2] 67 }

  condition:
    any of them
}