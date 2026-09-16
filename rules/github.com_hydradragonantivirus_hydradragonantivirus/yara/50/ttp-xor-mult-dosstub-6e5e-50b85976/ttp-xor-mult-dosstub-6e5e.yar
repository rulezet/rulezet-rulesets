rule TTP_XOR_MULT_DOSStub_6e5e {
  strings:
    $key_6e5e = { 3a 36 [2] 4e 2e [2] 09 2c [2] 4e 3d [2] 00 31 [2] 0c 3b [2] 1b 30 [2] 00 7e [2] 3d }

  condition:
    any of them
}