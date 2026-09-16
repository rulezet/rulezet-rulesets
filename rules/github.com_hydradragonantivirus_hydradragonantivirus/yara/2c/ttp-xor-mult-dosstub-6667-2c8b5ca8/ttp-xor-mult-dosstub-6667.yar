rule TTP_XOR_MULT_DOSStub_6667 {
  strings:
    $key_6667 = { 32 0f [2] 46 17 [2] 01 15 [2] 46 04 [2] 08 08 [2] 04 02 [2] 13 09 [2] 08 47 [2] 35 }

  condition:
    any of them
}