rule TTP_XOR_MULT_DOSStub_1d5e {
  strings:
    $key_1d5e = { 49 36 [2] 3d 2e [2] 7a 2c [2] 3d 3d [2] 73 31 [2] 7f 3b [2] 68 30 [2] 73 7e [2] 4e }

  condition:
    any of them
}