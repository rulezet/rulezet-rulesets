rule TTP_XOR_MULT_DOSStub_4d41 {
  strings:
    $key_4d41 = { 19 29 [2] 6d 31 [2] 2a 33 [2] 6d 22 [2] 23 2e [2] 2f 24 [2] 38 2f [2] 23 61 [2] 1e }

  condition:
    any of them
}