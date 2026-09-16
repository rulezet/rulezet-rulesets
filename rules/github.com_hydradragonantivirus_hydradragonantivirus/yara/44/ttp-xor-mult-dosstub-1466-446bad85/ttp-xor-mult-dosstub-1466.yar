rule TTP_XOR_MULT_DOSStub_1466 {
  strings:
    $key_1466 = { 40 0e [2] 34 16 [2] 73 14 [2] 34 05 [2] 7a 09 [2] 76 03 [2] 61 08 [2] 7a 46 [2] 47 }

  condition:
    any of them
}