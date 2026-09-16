rule TTP_XOR_MULT_DOSStub_73ae {
  strings:
    $key_73ae = { 27 c6 [2] 53 de [2] 14 dc [2] 53 cd [2] 1d c1 [2] 11 cb [2] 06 c0 [2] 1d 8e [2] 20 }

  condition:
    any of them
}