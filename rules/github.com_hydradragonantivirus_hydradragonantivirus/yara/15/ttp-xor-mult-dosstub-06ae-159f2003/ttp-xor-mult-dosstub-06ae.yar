rule TTP_XOR_MULT_DOSStub_06ae {
  strings:
    $key_06ae = { 52 c6 [2] 26 de [2] 61 dc [2] 26 cd [2] 68 c1 [2] 64 cb [2] 73 c0 [2] 68 8e [2] 55 }

  condition:
    any of them
}