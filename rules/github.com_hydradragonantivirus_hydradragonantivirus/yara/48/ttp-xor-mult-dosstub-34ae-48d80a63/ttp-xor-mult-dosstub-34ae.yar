rule TTP_XOR_MULT_DOSStub_34ae {
  strings:
    $key_34ae = { 60 c6 [2] 14 de [2] 53 dc [2] 14 cd [2] 5a c1 [2] 56 cb [2] 41 c0 [2] 5a 8e [2] 67 }

  condition:
    any of them
}