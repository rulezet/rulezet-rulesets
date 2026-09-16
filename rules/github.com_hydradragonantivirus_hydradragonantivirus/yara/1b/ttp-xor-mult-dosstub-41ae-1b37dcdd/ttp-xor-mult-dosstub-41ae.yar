rule TTP_XOR_MULT_DOSStub_41ae {
  strings:
    $key_41ae = { 15 c6 [2] 61 de [2] 26 dc [2] 61 cd [2] 2f c1 [2] 23 cb [2] 34 c0 [2] 2f 8e [2] 12 }

  condition:
    any of them
}