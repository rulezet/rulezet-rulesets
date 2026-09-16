rule TTP_XOR_MULT_DOSStub_56ae {
  strings:
    $key_56ae = { 02 c6 [2] 76 de [2] 31 dc [2] 76 cd [2] 38 c1 [2] 34 cb [2] 23 c0 [2] 38 8e [2] 05 }

  condition:
    any of them
}