rule TTP_XOR_MULT_DOSStub_2e5e {
  strings:
    $key_2e5e = { 7a 36 [2] 0e 2e [2] 49 2c [2] 0e 3d [2] 40 31 [2] 4c 3b [2] 5b 30 [2] 40 7e [2] 7d }

  condition:
    any of them
}