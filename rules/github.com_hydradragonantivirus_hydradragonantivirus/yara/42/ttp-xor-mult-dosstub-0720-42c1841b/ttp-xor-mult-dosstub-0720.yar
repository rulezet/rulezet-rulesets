rule TTP_XOR_MULT_DOSStub_0720 {
  strings:
    $key_0720 = { 53 48 [2] 27 50 [2] 60 52 [2] 27 43 [2] 69 4f [2] 65 45 [2] 72 4e [2] 69 00 [2] 54 }

  condition:
    any of them
}