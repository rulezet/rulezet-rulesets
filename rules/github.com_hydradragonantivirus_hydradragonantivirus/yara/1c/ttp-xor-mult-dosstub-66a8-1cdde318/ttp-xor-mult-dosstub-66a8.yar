rule TTP_XOR_MULT_DOSStub_66a8 {
  strings:
    $key_66a8 = { 32 c0 [2] 46 d8 [2] 01 da [2] 46 cb [2] 08 c7 [2] 04 cd [2] 13 c6 [2] 08 88 [2] 35 }

  condition:
    any of them
}