rule TTP_XOR_MULT_DOSStub_6336 {
  strings:
    $key_6336 = { 37 5e [2] 43 46 [2] 04 44 [2] 43 55 [2] 0d 59 [2] 01 53 [2] 16 58 [2] 0d 16 [2] 30 }

  condition:
    any of them
}