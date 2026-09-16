rule TTP_XOR_MULT_DOSStub_18f0 {
  strings:
    $key_18f0 = { 4c 98 [2] 38 80 [2] 7f 82 [2] 38 93 [2] 76 9f [2] 7a 95 [2] 6d 9e [2] 76 d0 [2] 4b }

  condition:
    any of them
}