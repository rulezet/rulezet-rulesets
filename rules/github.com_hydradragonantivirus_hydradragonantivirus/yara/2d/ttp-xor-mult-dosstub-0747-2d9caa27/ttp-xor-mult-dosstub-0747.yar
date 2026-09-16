rule TTP_XOR_MULT_DOSStub_0747 {
  strings:
    $key_0747 = { 53 2f [2] 27 37 [2] 60 35 [2] 27 24 [2] 69 28 [2] 65 22 [2] 72 29 [2] 69 67 [2] 54 }

  condition:
    any of them
}