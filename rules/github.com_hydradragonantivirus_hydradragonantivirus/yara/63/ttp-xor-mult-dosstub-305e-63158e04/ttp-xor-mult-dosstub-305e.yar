rule TTP_XOR_MULT_DOSStub_305e {
  strings:
    $key_305e = { 64 36 [2] 10 2e [2] 57 2c [2] 10 3d [2] 5e 31 [2] 52 3b [2] 45 30 [2] 5e 7e [2] 63 }

  condition:
    any of them
}