rule TTP_XOR_MULT_DOSStub_4e61 {
  strings:
    $key_4e61 = { 1a 09 [2] 6e 11 [2] 29 13 [2] 6e 02 [2] 20 0e [2] 2c 04 [2] 3b 0f [2] 20 41 [2] 1d }

  condition:
    any of them
}