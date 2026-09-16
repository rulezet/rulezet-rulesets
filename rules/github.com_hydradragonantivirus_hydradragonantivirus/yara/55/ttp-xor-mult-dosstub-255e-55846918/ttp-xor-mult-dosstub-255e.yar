rule TTP_XOR_MULT_DOSStub_255e {
  strings:
    $key_255e = { 71 36 [2] 05 2e [2] 42 2c [2] 05 3d [2] 4b 31 [2] 47 3b [2] 50 30 [2] 4b 7e [2] 76 }

  condition:
    any of them
}