rule TTP_XOR_MULT_DOSStub_71ae {
  strings:
    $key_71ae = { 25 c6 [2] 51 de [2] 16 dc [2] 51 cd [2] 1f c1 [2] 13 cb [2] 04 c0 [2] 1f 8e [2] 22 }

  condition:
    any of them
}