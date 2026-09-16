rule TTP_XOR_MULT_DOSStub_7a41 {
  strings:
    $key_7a41 = { 2e 29 [2] 5a 31 [2] 1d 33 [2] 5a 22 [2] 14 2e [2] 18 24 [2] 0f 2f [2] 14 61 [2] 29 }

  condition:
    any of them
}