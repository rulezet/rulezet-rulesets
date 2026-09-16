rule TTP_XOR_MULT_DOSStub_4ae0 {
  strings:
    $key_4ae0 = { 1e 88 [2] 6a 90 [2] 2d 92 [2] 6a 83 [2] 24 8f [2] 28 85 [2] 3f 8e [2] 24 c0 [2] 19 }

  condition:
    any of them
}