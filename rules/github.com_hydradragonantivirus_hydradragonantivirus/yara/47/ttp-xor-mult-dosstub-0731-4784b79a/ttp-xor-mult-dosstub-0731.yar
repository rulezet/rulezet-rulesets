rule TTP_XOR_MULT_DOSStub_0731 {
  strings:
    $key_0731 = { 53 59 [2] 27 41 [2] 60 43 [2] 27 52 [2] 69 5e [2] 65 54 [2] 72 5f [2] 69 11 [2] 54 }

  condition:
    any of them
}