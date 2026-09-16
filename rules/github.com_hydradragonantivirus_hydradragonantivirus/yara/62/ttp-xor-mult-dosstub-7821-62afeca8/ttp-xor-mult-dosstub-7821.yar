rule TTP_XOR_MULT_DOSStub_7821 {
  strings:
    $key_7821 = { 2c 49 [2] 58 51 [2] 1f 53 [2] 58 42 [2] 16 4e [2] 1a 44 [2] 0d 4f [2] 16 01 [2] 2b }

  condition:
    any of them
}