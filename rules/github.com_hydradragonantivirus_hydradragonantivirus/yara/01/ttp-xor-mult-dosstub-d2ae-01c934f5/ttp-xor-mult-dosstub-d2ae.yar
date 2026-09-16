rule TTP_XOR_MULT_DOSStub_d2ae {
  strings:
    $key_d2ae = { 86 c6 [2] f2 de [2] b5 dc [2] f2 cd [2] bc c1 [2] b0 cb [2] a7 c0 [2] bc 8e [2] 81 }

  condition:
    any of them
}