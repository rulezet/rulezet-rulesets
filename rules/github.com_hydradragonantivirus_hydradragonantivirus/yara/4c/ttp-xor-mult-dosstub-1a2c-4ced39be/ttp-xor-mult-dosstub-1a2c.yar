rule TTP_XOR_MULT_DOSStub_1a2c {
  strings:
    $key_1a2c = { 4e 44 [2] 3a 5c [2] 7d 5e [2] 3a 4f [2] 74 43 [2] 78 49 [2] 6f 42 [2] 74 0c [2] 49 }

  condition:
    any of them
}