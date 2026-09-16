rule TTP_XOR_MULT_DOSStub_6570 {
  strings:
    $key_6570 = { 31 18 [2] 45 00 [2] 02 02 [2] 45 13 [2] 0b 1f [2] 07 15 [2] 10 1e [2] 0b 50 [2] 36 }

  condition:
    any of them
}