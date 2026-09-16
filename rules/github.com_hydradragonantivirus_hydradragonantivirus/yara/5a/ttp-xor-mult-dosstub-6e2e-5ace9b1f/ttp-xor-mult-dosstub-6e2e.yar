rule TTP_XOR_MULT_DOSStub_6e2e {
  strings:
    $key_6e2e = { 3a 46 [2] 4e 5e [2] 09 5c [2] 4e 4d [2] 00 41 [2] 0c 4b [2] 1b 40 [2] 00 0e [2] 3d }

  condition:
    any of them
}