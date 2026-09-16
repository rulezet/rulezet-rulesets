rule TTP_XOR_MULT_DOSStub_0b50 {
  strings:
    $key_0b50 = { 5f 38 [2] 2b 20 [2] 6c 22 [2] 2b 33 [2] 65 3f [2] 69 35 [2] 7e 3e [2] 65 70 [2] 58 }

  condition:
    any of them
}