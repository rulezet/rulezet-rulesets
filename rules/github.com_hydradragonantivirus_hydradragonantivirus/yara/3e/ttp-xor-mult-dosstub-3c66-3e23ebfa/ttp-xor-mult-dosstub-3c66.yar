rule TTP_XOR_MULT_DOSStub_3c66 {
  strings:
    $key_3c66 = { 68 0e [2] 1c 16 [2] 5b 14 [2] 1c 05 [2] 52 09 [2] 5e 03 [2] 49 08 [2] 52 46 [2] 6f }

  condition:
    any of them
}