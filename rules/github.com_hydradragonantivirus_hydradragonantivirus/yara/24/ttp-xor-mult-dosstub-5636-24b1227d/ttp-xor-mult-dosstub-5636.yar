rule TTP_XOR_MULT_DOSStub_5636 {
  strings:
    $key_5636 = { 02 5e [2] 76 46 [2] 31 44 [2] 76 55 [2] 38 59 [2] 34 53 [2] 23 58 [2] 38 16 [2] 05 }

  condition:
    any of them
}