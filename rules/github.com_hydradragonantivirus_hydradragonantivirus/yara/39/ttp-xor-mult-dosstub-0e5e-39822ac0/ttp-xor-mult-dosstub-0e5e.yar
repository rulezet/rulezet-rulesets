rule TTP_XOR_MULT_DOSStub_0e5e {
  strings:
    $key_0e5e = { 5a 36 [2] 2e 2e [2] 69 2c [2] 2e 3d [2] 60 31 [2] 6c 3b [2] 7b 30 [2] 60 7e [2] 5d }

  condition:
    any of them
}