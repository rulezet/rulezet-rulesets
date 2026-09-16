rule TTP_XOR_MULT_DOSStub_27ae {
  strings:
    $key_27ae = { 73 c6 [2] 07 de [2] 40 dc [2] 07 cd [2] 49 c1 [2] 45 cb [2] 52 c0 [2] 49 8e [2] 74 }

  condition:
    any of them
}