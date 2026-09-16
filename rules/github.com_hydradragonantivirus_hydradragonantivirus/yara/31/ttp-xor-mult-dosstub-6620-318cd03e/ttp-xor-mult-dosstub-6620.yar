rule TTP_XOR_MULT_DOSStub_6620 {
  strings:
    $key_6620 = { 32 48 [2] 46 50 [2] 01 52 [2] 46 43 [2] 08 4f [2] 04 45 [2] 13 4e [2] 08 00 [2] 35 }

  condition:
    any of them
}