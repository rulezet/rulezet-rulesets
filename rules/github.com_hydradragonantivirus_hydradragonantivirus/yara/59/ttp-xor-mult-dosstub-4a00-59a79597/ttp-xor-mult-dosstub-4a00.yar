rule TTP_XOR_MULT_DOSStub_4a00 {
  strings:
    $key_4a00 = { 1e 68 [2] 6a 70 [2] 2d 72 [2] 6a 63 [2] 24 6f [2] 28 65 [2] 3f 6e [2] 24 20 [2] 19 }

  condition:
    any of them
}