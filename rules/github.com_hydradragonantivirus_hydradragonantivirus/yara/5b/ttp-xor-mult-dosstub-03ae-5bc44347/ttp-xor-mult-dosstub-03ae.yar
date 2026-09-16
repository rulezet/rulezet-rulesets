rule TTP_XOR_MULT_DOSStub_03ae {
  strings:
    $key_03ae = { 57 c6 [2] 23 de [2] 64 dc [2] 23 cd [2] 6d c1 [2] 61 cb [2] 76 c0 [2] 6d 8e [2] 50 }

  condition:
    any of them
}