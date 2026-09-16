rule TTP_XOR_MULT_DOSStub_2ff1 {
  strings:
    $key_2ff1 = { 7b 99 [2] 0f 81 [2] 48 83 [2] 0f 92 [2] 41 9e [2] 4d 94 [2] 5a 9f [2] 41 d1 [2] 7c }

  condition:
    any of them
}