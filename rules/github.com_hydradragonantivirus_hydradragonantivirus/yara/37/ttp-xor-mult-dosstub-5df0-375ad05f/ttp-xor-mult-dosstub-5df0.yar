rule TTP_XOR_MULT_DOSStub_5df0 {
  strings:
    $key_5df0 = { 09 98 [2] 7d 80 [2] 3a 82 [2] 7d 93 [2] 33 9f [2] 3f 95 [2] 28 9e [2] 33 d0 [2] 0e }

  condition:
    any of them
}