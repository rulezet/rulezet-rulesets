rule TTP_XOR_MULT_DOSStub_6677 {
  strings:
    $key_6677 = { 32 1f [2] 46 07 [2] 01 05 [2] 46 14 [2] 08 18 [2] 04 12 [2] 13 19 [2] 08 57 [2] 35 }

  condition:
    any of them
}