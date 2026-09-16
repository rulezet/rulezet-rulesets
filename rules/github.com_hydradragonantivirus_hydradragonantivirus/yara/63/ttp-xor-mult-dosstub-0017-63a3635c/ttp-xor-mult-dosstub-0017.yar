rule TTP_XOR_MULT_DOSStub_0017 {
  strings:
    $key_0017 = { 54 7f [2] 20 67 [2] 67 65 [2] 20 74 [2] 6e 78 [2] 62 72 [2] 75 79 [2] 6e 37 [2] 53 }

  condition:
    any of them
}