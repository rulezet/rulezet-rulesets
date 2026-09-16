rule TTP_XOR_MULT_DOSStub_0506 {
  strings:
    $key_0506 = { 51 6e [2] 25 76 [2] 62 74 [2] 25 65 [2] 6b 69 [2] 67 63 [2] 70 68 [2] 6b 26 [2] 56 }

  condition:
    any of them
}