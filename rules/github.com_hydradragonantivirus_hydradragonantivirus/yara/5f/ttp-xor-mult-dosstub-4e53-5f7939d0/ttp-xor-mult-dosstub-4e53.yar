rule TTP_XOR_MULT_DOSStub_4e53 {
  strings:
    $key_4e53 = { 1a 3b [2] 6e 23 [2] 29 21 [2] 6e 30 [2] 20 3c [2] 2c 36 [2] 3b 3d [2] 20 73 [2] 1d }

  condition:
    any of them
}