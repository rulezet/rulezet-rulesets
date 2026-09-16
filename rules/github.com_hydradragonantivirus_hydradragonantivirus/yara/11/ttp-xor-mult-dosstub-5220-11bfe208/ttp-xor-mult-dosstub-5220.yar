rule TTP_XOR_MULT_DOSStub_5220 {
  strings:
    $key_5220 = { 06 48 [2] 72 50 [2] 35 52 [2] 72 43 [2] 3c 4f [2] 30 45 [2] 27 4e [2] 3c 00 [2] 01 }

  condition:
    any of them
}