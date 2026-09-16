rule TTP_XOR_MULT_DOSStub_2af6 {
  strings:
    $key_2af6 = { 7e 9e [2] 0a 86 [2] 4d 84 [2] 0a 95 [2] 44 99 [2] 48 93 [2] 5f 98 [2] 44 d6 [2] 79 }

  condition:
    any of them
}