rule TTP_XOR_MULT_DOSStub_2a00 {
  strings:
    $key_2a00 = { 7e 68 [2] 0a 70 [2] 4d 72 [2] 0a 63 [2] 44 6f [2] 48 65 [2] 5f 6e [2] 44 20 [2] 79 }

  condition:
    any of them
}