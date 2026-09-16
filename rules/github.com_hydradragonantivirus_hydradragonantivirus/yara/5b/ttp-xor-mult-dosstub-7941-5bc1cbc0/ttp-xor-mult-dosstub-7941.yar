rule TTP_XOR_MULT_DOSStub_7941 {
  strings:
    $key_7941 = { 2d 29 [2] 59 31 [2] 1e 33 [2] 59 22 [2] 17 2e [2] 1b 24 [2] 0c 2f [2] 17 61 [2] 2a }

  condition:
    any of them
}