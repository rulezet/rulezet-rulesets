rule TTP_XOR_MULT_DOSStub_0b40 {
  strings:
    $key_0b40 = { 5f 28 [2] 2b 30 [2] 6c 32 [2] 2b 23 [2] 65 2f [2] 69 25 [2] 7e 2e [2] 65 60 [2] 58 }

  condition:
    any of them
}