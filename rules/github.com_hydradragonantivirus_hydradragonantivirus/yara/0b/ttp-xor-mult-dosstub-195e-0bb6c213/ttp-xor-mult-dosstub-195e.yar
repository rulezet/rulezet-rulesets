rule TTP_XOR_MULT_DOSStub_195e {
  strings:
    $key_195e = { 4d 36 [2] 39 2e [2] 7e 2c [2] 39 3d [2] 77 31 [2] 7b 3b [2] 6c 30 [2] 77 7e [2] 4a }

  condition:
    any of them
}