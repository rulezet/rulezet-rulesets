rule TTP_XOR_MULT_DOSStub_4a26 {
  strings:
    $key_4a26 = { 1e 4e [2] 6a 56 [2] 2d 54 [2] 6a 45 [2] 24 49 [2] 28 43 [2] 3f 48 [2] 24 06 [2] 19 }

  condition:
    any of them
}