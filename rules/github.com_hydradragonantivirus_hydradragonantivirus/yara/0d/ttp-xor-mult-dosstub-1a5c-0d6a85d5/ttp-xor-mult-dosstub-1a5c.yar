rule TTP_XOR_MULT_DOSStub_1a5c {
  strings:
    $key_1a5c = { 4e 34 [2] 3a 2c [2] 7d 2e [2] 3a 3f [2] 74 33 [2] 78 39 [2] 6f 32 [2] 74 7c [2] 49 }

  condition:
    any of them
}