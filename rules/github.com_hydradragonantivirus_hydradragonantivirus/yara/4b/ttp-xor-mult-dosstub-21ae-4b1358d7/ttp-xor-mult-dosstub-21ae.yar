rule TTP_XOR_MULT_DOSStub_21ae {
  strings:
    $key_21ae = { 75 c6 [2] 01 de [2] 46 dc [2] 01 cd [2] 4f c1 [2] 43 cb [2] 54 c0 [2] 4f 8e [2] 72 }

  condition:
    any of them
}