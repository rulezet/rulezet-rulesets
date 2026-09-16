rule TTP_XOR_MULT_DOSStub_205e {
  strings:
    $key_205e = { 74 36 [2] 00 2e [2] 47 2c [2] 00 3d [2] 4e 31 [2] 42 3b [2] 55 30 [2] 4e 7e [2] 73 }

  condition:
    any of them
}