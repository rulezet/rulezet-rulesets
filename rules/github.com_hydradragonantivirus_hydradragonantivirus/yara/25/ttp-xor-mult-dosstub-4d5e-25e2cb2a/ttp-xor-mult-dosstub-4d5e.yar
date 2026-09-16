rule TTP_XOR_MULT_DOSStub_4d5e {
  strings:
    $key_4d5e = { 19 36 [2] 6d 2e [2] 2a 2c [2] 6d 3d [2] 23 31 [2] 2f 3b [2] 38 30 [2] 23 7e [2] 1e }

  condition:
    any of them
}