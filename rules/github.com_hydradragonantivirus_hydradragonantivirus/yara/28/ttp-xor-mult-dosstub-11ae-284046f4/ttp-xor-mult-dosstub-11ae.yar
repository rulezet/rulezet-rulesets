rule TTP_XOR_MULT_DOSStub_11ae {
  strings:
    $key_11ae = { 45 c6 [2] 31 de [2] 76 dc [2] 31 cd [2] 7f c1 [2] 73 cb [2] 64 c0 [2] 7f 8e [2] 42 }

  condition:
    any of them
}