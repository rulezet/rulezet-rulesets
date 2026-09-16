rule TTP_XOR_MULT_DOSStub_355e {
  strings:
    $key_355e = { 61 36 [2] 15 2e [2] 52 2c [2] 15 3d [2] 5b 31 [2] 57 3b [2] 40 30 [2] 5b 7e [2] 66 }

  condition:
    any of them
}