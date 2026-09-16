rule TTP_XOR_MULT_DOSStub_3a2c {
  strings:
    $key_3a2c = { 6e 44 [2] 1a 5c [2] 5d 5e [2] 1a 4f [2] 54 43 [2] 58 49 [2] 4f 42 [2] 54 0c [2] 69 }

  condition:
    any of them
}