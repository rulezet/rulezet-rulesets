rule TTP_XOR_MULT_DOSStub_3400 {
  strings:
    $key_3400 = { 60 68 [2] 14 70 [2] 53 72 [2] 14 63 [2] 5a 6f [2] 56 65 [2] 41 6e [2] 5a 20 [2] 67 }

  condition:
    any of them
}