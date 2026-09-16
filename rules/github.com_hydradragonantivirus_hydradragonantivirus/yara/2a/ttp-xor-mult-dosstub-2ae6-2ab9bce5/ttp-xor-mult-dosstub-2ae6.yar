rule TTP_XOR_MULT_DOSStub_2ae6 {
  strings:
    $key_2ae6 = { 7e 8e [2] 0a 96 [2] 4d 94 [2] 0a 85 [2] 44 89 [2] 48 83 [2] 5f 88 [2] 44 c6 [2] 79 }

  condition:
    any of them
}