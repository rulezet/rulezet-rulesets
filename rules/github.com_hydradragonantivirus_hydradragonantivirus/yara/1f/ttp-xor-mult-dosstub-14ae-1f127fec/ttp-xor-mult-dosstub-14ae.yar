rule TTP_XOR_MULT_DOSStub_14ae {
  strings:
    $key_14ae = { 40 c6 [2] 34 de [2] 73 dc [2] 34 cd [2] 7a c1 [2] 76 cb [2] 61 c0 [2] 7a 8e [2] 47 }

  condition:
    any of them
}