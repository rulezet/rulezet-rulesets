rule TTP_XOR_MULT_DOSStub_7a5e {
  strings:
    $key_7a5e = { 2e 36 [2] 5a 2e [2] 1d 2c [2] 5a 3d [2] 14 31 [2] 18 3b [2] 0f 30 [2] 14 7e [2] 29 }

  condition:
    any of them
}