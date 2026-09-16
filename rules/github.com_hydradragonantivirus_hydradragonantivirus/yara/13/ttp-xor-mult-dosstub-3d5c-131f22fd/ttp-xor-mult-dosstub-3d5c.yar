rule TTP_XOR_MULT_DOSStub_3d5c {
  strings:
    $key_3d5c = { 69 34 [2] 1d 2c [2] 5a 2e [2] 1d 3f [2] 53 33 [2] 5f 39 [2] 48 32 [2] 53 7c [2] 6e }

  condition:
    any of them
}