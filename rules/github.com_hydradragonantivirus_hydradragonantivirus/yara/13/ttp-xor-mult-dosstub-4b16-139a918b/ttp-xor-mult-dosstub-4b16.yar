rule TTP_XOR_MULT_DOSStub_4b16 {
  strings:
    $key_4b16 = { 1f 7e [2] 6b 66 [2] 2c 64 [2] 6b 75 [2] 25 79 [2] 29 73 [2] 3e 78 [2] 25 36 [2] 18 }

  condition:
    any of them
}