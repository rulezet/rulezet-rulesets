rule TTP_XOR_MULT_DOSStub_4a41 {
  strings:
    $key_4a41 = { 1e 29 [2] 6a 31 [2] 2d 33 [2] 6a 22 [2] 24 2e [2] 28 24 [2] 3f 2f [2] 24 61 [2] 19 }

  condition:
    any of them
}