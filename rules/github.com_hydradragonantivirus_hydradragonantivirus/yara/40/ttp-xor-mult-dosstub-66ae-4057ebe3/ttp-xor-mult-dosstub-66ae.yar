rule TTP_XOR_MULT_DOSStub_66ae {
  strings:
    $key_66ae = { 32 c6 [2] 46 de [2] 01 dc [2] 46 cd [2] 08 c1 [2] 04 cb [2] 13 c0 [2] 08 8e [2] 35 }

  condition:
    any of them
}