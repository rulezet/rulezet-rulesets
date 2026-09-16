rule TTP_XOR_MULT_DOSStub_16ae {
  strings:
    $key_16ae = { 42 c6 [2] 36 de [2] 71 dc [2] 36 cd [2] 78 c1 [2] 74 cb [2] 63 c0 [2] 78 8e [2] 45 }

  condition:
    any of them
}