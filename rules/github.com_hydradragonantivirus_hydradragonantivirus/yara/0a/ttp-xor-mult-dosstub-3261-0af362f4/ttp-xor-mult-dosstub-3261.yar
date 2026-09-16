rule TTP_XOR_MULT_DOSStub_3261 {
  strings:
    $key_3261 = { 66 09 [2] 12 11 [2] 55 13 [2] 12 02 [2] 5c 0e [2] 50 04 [2] 47 0f [2] 5c 41 [2] 61 }

  condition:
    any of them
}