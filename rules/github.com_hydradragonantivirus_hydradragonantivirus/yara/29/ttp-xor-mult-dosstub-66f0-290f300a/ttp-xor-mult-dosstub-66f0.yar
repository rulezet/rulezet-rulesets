rule TTP_XOR_MULT_DOSStub_66f0 {
  strings:
    $key_66f0 = { 32 98 [2] 46 80 [2] 01 82 [2] 46 93 [2] 08 9f [2] 04 95 [2] 13 9e [2] 08 d0 [2] 35 }

  condition:
    any of them
}