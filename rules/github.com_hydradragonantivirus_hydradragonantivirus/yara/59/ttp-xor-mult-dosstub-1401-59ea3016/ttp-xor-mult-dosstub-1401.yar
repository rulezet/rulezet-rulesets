rule TTP_XOR_MULT_DOSStub_1401 {
  strings:
    $key_1401 = { 40 69 [2] 34 71 [2] 73 73 [2] 34 62 [2] 7a 6e [2] 76 64 [2] 61 6f [2] 7a 21 [2] 47 }

  condition:
    any of them
}