rule TTP_XOR_MULT_DOSStub_4a31 {
  strings:
    $key_4a31 = { 1e 59 [2] 6a 41 [2] 2d 43 [2] 6a 52 [2] 24 5e [2] 28 54 [2] 3f 5f [2] 24 11 [2] 19 }

  condition:
    any of them
}