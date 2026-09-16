rule TTP_XOR_MULT_DOSStub_4b11 {
  strings:
    $key_4b11 = { 1f 79 [2] 6b 61 [2] 2c 63 [2] 6b 72 [2] 25 7e [2] 29 74 [2] 3e 7f [2] 25 31 [2] 18 }

  condition:
    any of them
}