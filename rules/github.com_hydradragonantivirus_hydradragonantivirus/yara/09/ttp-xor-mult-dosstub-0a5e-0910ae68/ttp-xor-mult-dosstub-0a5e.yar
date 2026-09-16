rule TTP_XOR_MULT_DOSStub_0a5e {
  strings:
    $key_0a5e = { 5e 36 [2] 2a 2e [2] 6d 2c [2] 2a 3d [2] 64 31 [2] 68 3b [2] 7f 30 [2] 64 7e [2] 59 }

  condition:
    any of them
}