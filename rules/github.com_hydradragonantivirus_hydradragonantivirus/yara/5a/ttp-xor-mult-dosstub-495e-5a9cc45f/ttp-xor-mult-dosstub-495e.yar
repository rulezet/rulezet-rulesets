rule TTP_XOR_MULT_DOSStub_495e {
  strings:
    $key_495e = { 1d 36 [2] 69 2e [2] 2e 2c [2] 69 3d [2] 27 31 [2] 2b 3b [2] 3c 30 [2] 27 7e [2] 1a }

  condition:
    any of them
}