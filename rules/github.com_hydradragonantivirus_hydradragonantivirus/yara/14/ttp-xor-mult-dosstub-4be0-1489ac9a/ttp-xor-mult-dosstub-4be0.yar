rule TTP_XOR_MULT_DOSStub_4be0 {
  strings:
    $key_4be0 = { 1f 88 [2] 6b 90 [2] 2c 92 [2] 6b 83 [2] 25 8f [2] 29 85 [2] 3e 8e [2] 25 c0 [2] 18 }

  condition:
    any of them
}