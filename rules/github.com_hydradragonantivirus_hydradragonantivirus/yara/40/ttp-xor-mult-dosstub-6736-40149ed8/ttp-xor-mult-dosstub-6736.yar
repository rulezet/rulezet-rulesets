rule TTP_XOR_MULT_DOSStub_6736 {
  strings:
    $key_6736 = { 33 5e [2] 47 46 [2] 00 44 [2] 47 55 [2] 09 59 [2] 05 53 [2] 12 58 [2] 09 16 [2] 34 }

  condition:
    any of them
}