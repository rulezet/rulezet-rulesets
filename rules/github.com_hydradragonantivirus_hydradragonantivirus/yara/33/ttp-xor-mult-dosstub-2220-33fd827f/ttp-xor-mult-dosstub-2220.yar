rule TTP_XOR_MULT_DOSStub_2220 {
  strings:
    $key_2220 = { 76 48 [2] 02 50 [2] 45 52 [2] 02 43 [2] 4c 4f [2] 40 45 [2] 57 4e [2] 4c 00 [2] 71 }

  condition:
    any of them
}