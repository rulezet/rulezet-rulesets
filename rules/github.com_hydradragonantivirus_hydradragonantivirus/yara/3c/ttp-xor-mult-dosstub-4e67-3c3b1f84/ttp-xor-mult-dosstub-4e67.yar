rule TTP_XOR_MULT_DOSStub_4e67 {
  strings:
    $key_4e67 = { 1a 0f [2] 6e 17 [2] 29 15 [2] 6e 04 [2] 20 08 [2] 2c 02 [2] 3b 09 [2] 20 47 [2] 1d }

  condition:
    any of them
}