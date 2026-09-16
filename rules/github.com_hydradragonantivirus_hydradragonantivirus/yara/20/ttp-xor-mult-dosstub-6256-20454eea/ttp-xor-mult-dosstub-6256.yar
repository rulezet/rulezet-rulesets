rule TTP_XOR_MULT_DOSStub_6256 {
  strings:
    $key_6256 = { 36 3e [2] 42 26 [2] 05 24 [2] 42 35 [2] 0c 39 [2] 00 33 [2] 17 38 [2] 0c 76 [2] 31 }

  condition:
    any of them
}