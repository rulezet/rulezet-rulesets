rule TTP_XOR_MULT_DOSStub_2a5e {
  strings:
    $key_2a5e = { 7e 36 [2] 0a 2e [2] 4d 2c [2] 0a 3d [2] 44 31 [2] 48 3b [2] 5f 30 [2] 44 7e [2] 79 }

  condition:
    any of them
}