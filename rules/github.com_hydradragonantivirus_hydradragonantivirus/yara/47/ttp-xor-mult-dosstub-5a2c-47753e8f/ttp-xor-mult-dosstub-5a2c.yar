rule TTP_XOR_MULT_DOSStub_5a2c {
  strings:
    $key_5a2c = { 0e 44 [2] 7a 5c [2] 3d 5e [2] 7a 4f [2] 34 43 [2] 38 49 [2] 2f 42 [2] 34 0c [2] 09 }

  condition:
    any of them
}