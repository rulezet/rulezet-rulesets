rule TTP_XOR_MULT_DOSStub_2231 {
  strings:
    $key_2231 = { 76 59 [2] 02 41 [2] 45 43 [2] 02 52 [2] 4c 5e [2] 40 54 [2] 57 5f [2] 4c 11 [2] 71 }

  condition:
    any of them
}