rule TTP_XOR_MULT_DOSStub_4731 {
  strings:
    $key_4731 = { 13 59 [2] 67 41 [2] 20 43 [2] 67 52 [2] 29 5e [2] 25 54 [2] 32 5f [2] 29 11 [2] 14 }

  condition:
    any of them
}