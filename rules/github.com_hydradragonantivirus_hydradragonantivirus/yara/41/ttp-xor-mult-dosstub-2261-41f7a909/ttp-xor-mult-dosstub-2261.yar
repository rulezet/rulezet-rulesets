rule TTP_XOR_MULT_DOSStub_2261 {
  strings:
    $key_2261 = { 76 09 [2] 02 11 [2] 45 13 [2] 02 02 [2] 4c 0e [2] 40 04 [2] 57 0f [2] 4c 41 [2] 71 }

  condition:
    any of them
}