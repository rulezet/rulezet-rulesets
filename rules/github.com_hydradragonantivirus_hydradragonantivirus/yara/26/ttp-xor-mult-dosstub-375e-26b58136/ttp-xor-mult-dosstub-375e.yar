rule TTP_XOR_MULT_DOSStub_375e {
  strings:
    $key_375e = { 63 36 [2] 17 2e [2] 50 2c [2] 17 3d [2] 59 31 [2] 55 3b [2] 42 30 [2] 59 7e [2] 64 }

  condition:
    any of them
}