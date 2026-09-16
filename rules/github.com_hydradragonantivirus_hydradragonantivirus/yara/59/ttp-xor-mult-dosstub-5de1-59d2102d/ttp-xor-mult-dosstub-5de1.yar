rule TTP_XOR_MULT_DOSStub_5de1 {
  strings:
    $key_5de1 = { 09 89 [2] 7d 91 [2] 3a 93 [2] 7d 82 [2] 33 8e [2] 3f 84 [2] 28 8f [2] 33 c1 [2] 0e }

  condition:
    any of them
}