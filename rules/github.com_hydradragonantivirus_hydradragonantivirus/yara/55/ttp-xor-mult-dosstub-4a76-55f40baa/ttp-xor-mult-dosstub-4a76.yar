rule TTP_XOR_MULT_DOSStub_4a76 {
  strings:
    $key_4a76 = { 1e 1e [2] 6a 06 [2] 2d 04 [2] 6a 15 [2] 24 19 [2] 28 13 [2] 3f 18 [2] 24 56 [2] 19 }

  condition:
    any of them
}