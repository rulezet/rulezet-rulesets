rule TTP_XOR_MULT_DOSStub_4ef9 {
  strings:
    $key_4ef9 = { 1a 91 [2] 6e 89 [2] 29 8b [2] 6e 9a [2] 20 96 [2] 2c 9c [2] 3b 97 [2] 20 d9 [2] 1d }

  condition:
    any of them
}