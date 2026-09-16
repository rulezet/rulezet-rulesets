rule TTP_XOR_MULT_DOSStub_5066 {
  strings:
    $key_5066 = { 04 0e [2] 70 16 [2] 37 14 [2] 70 05 [2] 3e 09 [2] 32 03 [2] 25 08 [2] 3e 46 [2] 03 }

  condition:
    any of them
}