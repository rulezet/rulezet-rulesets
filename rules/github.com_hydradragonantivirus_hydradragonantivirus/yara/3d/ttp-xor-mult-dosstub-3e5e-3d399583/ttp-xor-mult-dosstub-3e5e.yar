rule TTP_XOR_MULT_DOSStub_3e5e {
  strings:
    $key_3e5e = { 6a 36 [2] 1e 2e [2] 59 2c [2] 1e 3d [2] 50 31 [2] 5c 3b [2] 4b 30 [2] 50 7e [2] 6d }

  condition:
    any of them
}