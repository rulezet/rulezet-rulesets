rule TTP_XOR_MULT_DOSStub_6df6 {
  strings:
    $key_6df6 = { 39 9e [2] 4d 86 [2] 0a 84 [2] 4d 95 [2] 03 99 [2] 0f 93 [2] 18 98 [2] 03 d6 [2] 3e }

  condition:
    any of them
}