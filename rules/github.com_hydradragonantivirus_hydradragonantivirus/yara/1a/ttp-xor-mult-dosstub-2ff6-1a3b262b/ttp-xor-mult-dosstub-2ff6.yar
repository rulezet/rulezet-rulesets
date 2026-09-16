rule TTP_XOR_MULT_DOSStub_2ff6 {
  strings:
    $key_2ff6 = { 7b 9e [2] 0f 86 [2] 48 84 [2] 0f 95 [2] 41 99 [2] 4d 93 [2] 5a 98 [2] 41 d6 [2] 7c }

  condition:
    any of them
}