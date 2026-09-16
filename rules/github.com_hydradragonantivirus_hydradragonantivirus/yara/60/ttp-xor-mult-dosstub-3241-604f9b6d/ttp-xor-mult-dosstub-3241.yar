rule TTP_XOR_MULT_DOSStub_3241 {
  strings:
    $key_3241 = { 66 29 [2] 12 31 [2] 55 33 [2] 12 22 [2] 5c 2e [2] 50 24 [2] 47 2f [2] 5c 61 [2] 61 }

  condition:
    any of them
}