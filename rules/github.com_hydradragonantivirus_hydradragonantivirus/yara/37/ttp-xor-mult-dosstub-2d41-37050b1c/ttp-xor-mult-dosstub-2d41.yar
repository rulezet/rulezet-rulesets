rule TTP_XOR_MULT_DOSStub_2d41 {
  strings:
    $key_2d41 = { 79 29 [2] 0d 31 [2] 4a 33 [2] 0d 22 [2] 43 2e [2] 4f 24 [2] 58 2f [2] 43 61 [2] 7e }

  condition:
    any of them
}