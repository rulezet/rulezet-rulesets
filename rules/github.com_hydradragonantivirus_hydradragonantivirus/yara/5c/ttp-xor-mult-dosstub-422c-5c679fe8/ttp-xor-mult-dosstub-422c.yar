rule TTP_XOR_MULT_DOSStub_422c {
  strings:
    $key_422c = { 16 44 [2] 62 5c [2] 25 5e [2] 62 4f [2] 2c 43 [2] 20 49 [2] 37 42 [2] 2c 0c [2] 11 }

  condition:
    any of them
}