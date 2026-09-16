rule TTP_XOR_MULT_DOSStub_0b76 {
  strings:
    $key_0b76 = { 5f 1e [2] 2b 06 [2] 6c 04 [2] 2b 15 [2] 65 19 [2] 69 13 [2] 7e 18 [2] 65 56 [2] 58 }

  condition:
    any of them
}