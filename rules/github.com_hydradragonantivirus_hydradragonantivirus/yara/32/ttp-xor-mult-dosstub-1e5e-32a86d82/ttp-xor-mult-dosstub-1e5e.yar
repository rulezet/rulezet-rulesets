rule TTP_XOR_MULT_DOSStub_1e5e {
  strings:
    $key_1e5e = { 4a 36 [2] 3e 2e [2] 79 2c [2] 3e 3d [2] 70 31 [2] 7c 3b [2] 6b 30 [2] 70 7e [2] 4d }

  condition:
    any of them
}