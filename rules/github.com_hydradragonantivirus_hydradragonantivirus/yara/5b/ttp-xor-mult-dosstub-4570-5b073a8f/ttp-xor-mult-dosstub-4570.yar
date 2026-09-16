rule TTP_XOR_MULT_DOSStub_4570 {
  strings:
    $key_4570 = { 11 18 [2] 65 00 [2] 22 02 [2] 65 13 [2] 2b 1f [2] 27 15 [2] 30 1e [2] 2b 50 [2] 16 }

  condition:
    any of them
}