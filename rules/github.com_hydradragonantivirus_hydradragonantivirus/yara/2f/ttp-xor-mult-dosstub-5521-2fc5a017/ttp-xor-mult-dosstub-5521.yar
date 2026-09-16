rule TTP_XOR_MULT_DOSStub_5521 {
  strings:
    $key_5521 = { 01 49 [2] 75 51 [2] 32 53 [2] 75 42 [2] 3b 4e [2] 37 44 [2] 20 4f [2] 3b 01 [2] 06 }

  condition:
    any of them
}