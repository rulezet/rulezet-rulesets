rule TTP_XOR_MULT_DOSStub_4f40 {
  strings:
    $key_4f40 = { 1b 28 [2] 6f 30 [2] 28 32 [2] 6f 23 [2] 21 2f [2] 2d 25 [2] 3a 2e [2] 21 60 [2] 1c }

  condition:
    any of them
}