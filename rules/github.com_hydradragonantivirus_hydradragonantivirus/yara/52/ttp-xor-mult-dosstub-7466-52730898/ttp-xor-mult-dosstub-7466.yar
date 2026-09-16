rule TTP_XOR_MULT_DOSStub_7466 {
  strings:
    $key_7466 = { 20 0e [2] 54 16 [2] 13 14 [2] 54 05 [2] 1a 09 [2] 16 03 [2] 01 08 [2] 1a 46 [2] 27 }

  condition:
    any of them
}