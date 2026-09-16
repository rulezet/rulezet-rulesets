rule TTP_XOR_MULT_DOSStub_7241 {
  strings:
    $key_7241 = { 26 29 [2] 52 31 [2] 15 33 [2] 52 22 [2] 1c 2e [2] 10 24 [2] 07 2f [2] 1c 61 [2] 21 }

  condition:
    any of them
}