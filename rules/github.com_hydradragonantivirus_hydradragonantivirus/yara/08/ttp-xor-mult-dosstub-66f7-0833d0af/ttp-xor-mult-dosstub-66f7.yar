rule TTP_XOR_MULT_DOSStub_66f7 {
  strings:
    $key_66f7 = { 32 9f [2] 46 87 [2] 01 85 [2] 46 94 [2] 08 98 [2] 04 92 [2] 13 99 [2] 08 d7 [2] 35 }

  condition:
    any of them
}