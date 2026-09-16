rule TTP_XOR_MULT_DOSStub_18e0 {
  strings:
    $key_18e0 = { 4c 88 [2] 38 90 [2] 7f 92 [2] 38 83 [2] 76 8f [2] 7a 85 [2] 6d 8e [2] 76 c0 [2] 4b }

  condition:
    any of them
}