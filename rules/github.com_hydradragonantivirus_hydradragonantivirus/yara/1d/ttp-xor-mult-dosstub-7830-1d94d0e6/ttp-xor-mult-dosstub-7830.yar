rule TTP_XOR_MULT_DOSStub_7830 {
  strings:
    $key_7830 = { 2c 58 [2] 58 40 [2] 1f 42 [2] 58 53 [2] 16 5f [2] 1a 55 [2] 0d 5e [2] 16 10 [2] 2b }

  condition:
    any of them
}