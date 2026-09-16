rule TTP_XOR_MULT_DOSStub_36ae {
  strings:
    $key_36ae = { 62 c6 [2] 16 de [2] 51 dc [2] 16 cd [2] 58 c1 [2] 54 cb [2] 43 c0 [2] 58 8e [2] 65 }

  condition:
    any of them
}