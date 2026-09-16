rule TTP_XOR_MULT_DOSStub_6661 {
  strings:
    $key_6661 = { 32 09 [2] 46 11 [2] 01 13 [2] 46 02 [2] 08 0e [2] 04 04 [2] 13 0f [2] 08 41 [2] 35 }

  condition:
    any of them
}