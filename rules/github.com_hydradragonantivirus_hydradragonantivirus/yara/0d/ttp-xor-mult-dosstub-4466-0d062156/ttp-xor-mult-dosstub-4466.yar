rule TTP_XOR_MULT_DOSStub_4466 {
  strings:
    $key_4466 = { 10 0e [2] 64 16 [2] 23 14 [2] 64 05 [2] 2a 09 [2] 26 03 [2] 31 08 [2] 2a 46 [2] 17 }

  condition:
    any of them
}