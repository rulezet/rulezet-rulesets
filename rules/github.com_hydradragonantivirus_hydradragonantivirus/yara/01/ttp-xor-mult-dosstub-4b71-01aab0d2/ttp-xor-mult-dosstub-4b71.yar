rule TTP_XOR_MULT_DOSStub_4b71 {
  strings:
    $key_4b71 = { 1f 19 [2] 6b 01 [2] 2c 03 [2] 6b 12 [2] 25 1e [2] 29 14 [2] 3e 1f [2] 25 51 [2] 18 }

  condition:
    any of them
}