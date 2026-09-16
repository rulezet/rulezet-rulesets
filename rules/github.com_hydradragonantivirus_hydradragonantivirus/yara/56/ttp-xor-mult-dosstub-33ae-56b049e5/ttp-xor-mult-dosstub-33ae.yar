rule TTP_XOR_MULT_DOSStub_33ae {
  strings:
    $key_33ae = { 67 c6 [2] 13 de [2] 54 dc [2] 13 cd [2] 5d c1 [2] 51 cb [2] 46 c0 [2] 5d 8e [2] 60 }

  condition:
    any of them
}