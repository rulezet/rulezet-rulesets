rule TTP_XOR_MULT_DOSStub_4a11 {
  strings:
    $key_4a11 = { 1e 79 [2] 6a 61 [2] 2d 63 [2] 6a 72 [2] 24 7e [2] 28 74 [2] 3f 7f [2] 24 31 [2] 19 }

  condition:
    any of them
}