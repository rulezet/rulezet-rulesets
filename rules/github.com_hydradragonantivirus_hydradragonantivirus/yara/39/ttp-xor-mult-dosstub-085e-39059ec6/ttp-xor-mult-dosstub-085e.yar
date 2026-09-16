rule TTP_XOR_MULT_DOSStub_085e {
  strings:
    $key_085e = { 5c 36 [2] 28 2e [2] 6f 2c [2] 28 3d [2] 66 31 [2] 6a 3b [2] 7d 30 [2] 66 7e [2] 5b }

  condition:
    any of them
}