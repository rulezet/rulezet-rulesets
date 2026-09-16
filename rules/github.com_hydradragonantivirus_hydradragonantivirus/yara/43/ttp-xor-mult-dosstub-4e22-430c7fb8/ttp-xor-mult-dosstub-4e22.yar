rule TTP_XOR_MULT_DOSStub_4e22 {
  strings:
    $key_4e22 = { 1a 4a [2] 6e 52 [2] 29 50 [2] 6e 41 [2] 20 4d [2] 2c 47 [2] 3b 4c [2] 20 02 [2] 1d }

  condition:
    any of them
}