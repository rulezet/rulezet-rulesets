rule TTP_XOR_MULT_DOSStub_7166 {
  strings:
    $key_7166 = { 25 0e [2] 51 16 [2] 16 14 [2] 51 05 [2] 1f 09 [2] 13 03 [2] 04 08 [2] 1f 46 [2] 22 }

  condition:
    any of them
}