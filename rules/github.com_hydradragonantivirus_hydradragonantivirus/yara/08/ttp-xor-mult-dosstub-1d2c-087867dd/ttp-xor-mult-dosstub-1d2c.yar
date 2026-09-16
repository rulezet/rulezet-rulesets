rule TTP_XOR_MULT_DOSStub_1d2c {
  strings:
    $key_1d2c = { 49 44 [2] 3d 5c [2] 7a 5e [2] 3d 4f [2] 73 43 [2] 7f 49 [2] 68 42 [2] 73 0c [2] 4e }

  condition:
    any of them
}