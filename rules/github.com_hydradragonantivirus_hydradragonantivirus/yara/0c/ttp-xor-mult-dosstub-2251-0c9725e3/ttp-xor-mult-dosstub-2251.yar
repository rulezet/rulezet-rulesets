rule TTP_XOR_MULT_DOSStub_2251 {
  strings:
    $key_2251 = { 76 39 [2] 02 21 [2] 45 23 [2] 02 32 [2] 4c 3e [2] 40 34 [2] 57 3f [2] 4c 71 [2] 71 }

  condition:
    any of them
}