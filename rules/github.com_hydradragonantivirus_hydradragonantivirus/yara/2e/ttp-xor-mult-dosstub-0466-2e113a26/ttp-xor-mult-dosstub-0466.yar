rule TTP_XOR_MULT_DOSStub_0466 {
  strings:
    $key_0466 = { 50 0e [2] 24 16 [2] 63 14 [2] 24 05 [2] 6a 09 [2] 66 03 [2] 71 08 [2] 6a 46 [2] 57 }

  condition:
    any of them
}