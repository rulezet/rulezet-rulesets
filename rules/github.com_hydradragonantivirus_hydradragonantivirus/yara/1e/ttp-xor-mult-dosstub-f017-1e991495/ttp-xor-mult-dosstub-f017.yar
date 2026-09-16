rule TTP_XOR_MULT_DOSStub_f017 {
  strings:
    $key_f017 = { a4 7f [2] d0 67 [2] 97 65 [2] d0 74 [2] 9e 78 [2] 92 72 [2] 85 79 [2] 9e 37 [2] a3 }

  condition:
    any of them
}