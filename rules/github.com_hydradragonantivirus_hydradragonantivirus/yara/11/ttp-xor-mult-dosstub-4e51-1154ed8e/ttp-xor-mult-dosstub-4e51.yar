rule TTP_XOR_MULT_DOSStub_4e51 {
  strings:
    $key_4e51 = { 1a 39 [2] 6e 21 [2] 29 23 [2] 6e 32 [2] 20 3e [2] 2c 34 [2] 3b 3f [2] 20 71 [2] 1d }

  condition:
    any of them
}