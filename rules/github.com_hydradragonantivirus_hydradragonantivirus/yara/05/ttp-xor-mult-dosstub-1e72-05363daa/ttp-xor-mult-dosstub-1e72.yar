rule TTP_XOR_MULT_DOSStub_1e72 {
  strings:
    $key_1e72 = { 4a 1a [2] 3e 02 [2] 79 00 [2] 3e 11 [2] 70 1d [2] 7c 17 [2] 6b 1c [2] 70 52 [2] 4d }

  condition:
    any of them
}