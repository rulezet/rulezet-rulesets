rule TTP_XOR_MULT_DOSStub_39f6 {
  strings:
    $key_39f6 = { 6d 9e [2] 19 86 [2] 5e 84 [2] 19 95 [2] 57 99 [2] 5b 93 [2] 4c 98 [2] 57 d6 [2] 6a }

  condition:
    any of them
}