rule TTP_XOR_MULT_DOSStub_6576 {
  strings:
    $key_6576 = { 31 1e [2] 45 06 [2] 02 04 [2] 45 15 [2] 0b 19 [2] 07 13 [2] 10 18 [2] 0b 56 [2] 36 }

  condition:
    any of them
}