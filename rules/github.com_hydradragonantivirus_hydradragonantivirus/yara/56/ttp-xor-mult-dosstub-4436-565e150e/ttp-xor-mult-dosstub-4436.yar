rule TTP_XOR_MULT_DOSStub_4436 {
  strings:
    $key_4436 = { 10 5e [2] 64 46 [2] 23 44 [2] 64 55 [2] 2a 59 [2] 26 53 [2] 31 58 [2] 2a 16 [2] 17 }

  condition:
    any of them
}