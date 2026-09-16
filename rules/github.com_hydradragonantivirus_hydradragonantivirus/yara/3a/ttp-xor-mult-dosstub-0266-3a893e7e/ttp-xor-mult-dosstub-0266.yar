rule TTP_XOR_MULT_DOSStub_0266 {
  strings:
    $key_0266 = { 56 0e [2] 22 16 [2] 65 14 [2] 22 05 [2] 6c 09 [2] 60 03 [2] 77 08 [2] 6c 46 [2] 51 }

  condition:
    any of them
}