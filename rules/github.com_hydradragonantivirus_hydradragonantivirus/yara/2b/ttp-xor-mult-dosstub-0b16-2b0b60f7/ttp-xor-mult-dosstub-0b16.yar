rule TTP_XOR_MULT_DOSStub_0b16 {
  strings:
    $key_0b16 = { 5f 7e [2] 2b 66 [2] 6c 64 [2] 2b 75 [2] 65 79 [2] 69 73 [2] 7e 78 [2] 65 36 [2] 58 }

  condition:
    any of them
}