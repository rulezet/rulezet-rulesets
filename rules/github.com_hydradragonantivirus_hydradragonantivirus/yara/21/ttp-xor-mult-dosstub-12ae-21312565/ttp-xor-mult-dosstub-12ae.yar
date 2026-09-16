rule TTP_XOR_MULT_DOSStub_12ae {
  strings:
    $key_12ae = { 46 c6 [2] 32 de [2] 75 dc [2] 32 cd [2] 7c c1 [2] 70 cb [2] 67 c0 [2] 7c 8e [2] 41 }

  condition:
    any of them
}