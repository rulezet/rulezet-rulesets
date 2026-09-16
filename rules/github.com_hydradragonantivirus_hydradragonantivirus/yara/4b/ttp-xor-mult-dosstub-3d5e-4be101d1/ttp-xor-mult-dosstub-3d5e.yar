rule TTP_XOR_MULT_DOSStub_3d5e {
  strings:
    $key_3d5e = { 69 36 [2] 1d 2e [2] 5a 2c [2] 1d 3d [2] 53 31 [2] 5f 3b [2] 48 30 [2] 53 7e [2] 6e }

  condition:
    any of them
}