rule TTP_XOR_MULT_DOSStub_f047 {
  strings:
    $key_f047 = { a4 2f [2] d0 37 [2] 97 35 [2] d0 24 [2] 9e 28 [2] 92 22 [2] 85 29 [2] 9e 67 [2] a3 }

  condition:
    any of them
}