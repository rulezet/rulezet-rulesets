rule TTP_XOR_MULT_DOSStub_3d2c {
  strings:
    $key_3d2c = { 69 44 [2] 1d 5c [2] 5a 5e [2] 1d 4f [2] 53 43 [2] 5f 49 [2] 48 42 [2] 53 0c [2] 6e }

  condition:
    any of them
}