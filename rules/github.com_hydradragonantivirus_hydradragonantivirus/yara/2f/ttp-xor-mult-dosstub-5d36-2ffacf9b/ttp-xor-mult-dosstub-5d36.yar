rule TTP_XOR_MULT_DOSStub_5d36 {
  strings:
    $key_5d36 = { 09 5e [2] 7d 46 [2] 3a 44 [2] 7d 55 [2] 33 59 [2] 3f 53 [2] 28 58 [2] 33 16 [2] 0e }

  condition:
    any of them
}