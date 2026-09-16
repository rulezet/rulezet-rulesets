rule TTP_XOR_MULT_DOSStub_7266 {
  strings:
    $key_7266 = { 26 0e [2] 52 16 [2] 15 14 [2] 52 05 [2] 1c 09 [2] 10 03 [2] 07 08 [2] 1c 46 [2] 21 }

  condition:
    any of them
}