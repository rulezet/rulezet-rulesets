rule TTP_XOR_MULT_DOSStub_0736 {
  strings:
    $key_0736 = { 53 5e [2] 27 46 [2] 60 44 [2] 27 55 [2] 69 59 [2] 65 53 [2] 72 58 [2] 69 16 [2] 54 }

  condition:
    any of them
}