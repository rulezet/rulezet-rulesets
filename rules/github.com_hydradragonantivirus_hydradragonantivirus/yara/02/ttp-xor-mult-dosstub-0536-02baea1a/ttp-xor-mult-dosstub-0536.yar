rule TTP_XOR_MULT_DOSStub_0536 {
  strings:
    $key_0536 = { 51 5e [2] 25 46 [2] 62 44 [2] 25 55 [2] 6b 59 [2] 67 53 [2] 70 58 [2] 6b 16 [2] 56 }

  condition:
    any of them
}