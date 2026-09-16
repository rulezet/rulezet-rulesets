rule TTP_XOR_MULT_DOSStub_6ff1 {
  strings:
    $key_6ff1 = { 3b 99 [2] 4f 81 [2] 08 83 [2] 4f 92 [2] 01 9e [2] 0d 94 [2] 1a 9f [2] 01 d1 [2] 3c }

  condition:
    any of them
}