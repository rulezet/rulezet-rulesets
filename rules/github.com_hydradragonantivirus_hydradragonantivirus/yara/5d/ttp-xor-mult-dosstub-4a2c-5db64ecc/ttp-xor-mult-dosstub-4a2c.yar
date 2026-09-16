rule TTP_XOR_MULT_DOSStub_4a2c {
  strings:
    $key_4a2c = { 1e 44 [2] 6a 5c [2] 2d 5e [2] 6a 4f [2] 24 43 [2] 28 49 [2] 3f 42 [2] 24 0c [2] 19 }

  condition:
    any of them
}