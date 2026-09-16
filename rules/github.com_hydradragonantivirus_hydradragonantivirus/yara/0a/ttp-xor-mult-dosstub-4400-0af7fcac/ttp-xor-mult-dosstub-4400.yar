rule TTP_XOR_MULT_DOSStub_4400 {
  strings:
    $key_4400 = { 10 68 [2] 64 70 [2] 23 72 [2] 64 63 [2] 2a 6f [2] 26 65 [2] 31 6e [2] 2a 20 [2] 17 }

  condition:
    any of them
}