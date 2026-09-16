rule TTP_XOR_MULT_DOSStub_57ae {
  strings:
    $key_57ae = { 03 c6 [2] 77 de [2] 30 dc [2] 77 cd [2] 39 c1 [2] 35 cb [2] 22 c0 [2] 39 8e [2] 04 }

  condition:
    any of them
}