rule TTP_XOR_MULT_DOSStub_22ae {
  strings:
    $key_22ae = { 76 c6 [2] 02 de [2] 45 dc [2] 02 cd [2] 4c c1 [2] 40 cb [2] 57 c0 [2] 4c 8e [2] 71 }

  condition:
    any of them
}