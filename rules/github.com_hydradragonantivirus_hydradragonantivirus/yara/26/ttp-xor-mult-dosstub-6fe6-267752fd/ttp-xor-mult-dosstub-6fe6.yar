rule TTP_XOR_MULT_DOSStub_6fe6 {
  strings:
    $key_6fe6 = { 3b 8e [2] 4f 96 [2] 08 94 [2] 4f 85 [2] 01 89 [2] 0d 83 [2] 1a 88 [2] 01 c6 [2] 3c }

  condition:
    any of them
}