rule TTP_XOR_MULT_DOSStub_68f0 {
  strings:
    $key_68f0 = { 3c 98 [2] 48 80 [2] 0f 82 [2] 48 93 [2] 06 9f [2] 0a 95 [2] 1d 9e [2] 06 d0 [2] 3b }

  condition:
    any of them
}