rule TTP_XOR_MULT_DOSStub_6657 {
  strings:
    $key_6657 = { 32 3f [2] 46 27 [2] 01 25 [2] 46 34 [2] 08 38 [2] 04 32 [2] 13 39 [2] 08 77 [2] 35 }

  condition:
    any of them
}