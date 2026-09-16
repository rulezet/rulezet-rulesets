rule TTP_XOR_MULT_DOSStub_3536 {
  strings:
    $key_3536 = { 61 5e [2] 15 46 [2] 52 44 [2] 15 55 [2] 5b 59 [2] 57 53 [2] 40 58 [2] 5b 16 [2] 66 }

  condition:
    any of them
}