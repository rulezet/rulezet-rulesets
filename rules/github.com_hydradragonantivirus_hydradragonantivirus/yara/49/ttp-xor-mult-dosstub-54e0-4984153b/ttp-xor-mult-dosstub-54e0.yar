rule TTP_XOR_MULT_DOSStub_54e0 {
  strings:
    $key_54e0 = { 00 88 [2] 74 90 [2] 33 92 [2] 74 83 [2] 3a 8f [2] 36 85 [2] 21 8e [2] 3a c0 [2] 07 }

  condition:
    any of them
}