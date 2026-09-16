rule TTP_XOR_MULT_DOSStub_325e {
  strings:
    $key_325e = { 66 36 [2] 12 2e [2] 55 2c [2] 12 3d [2] 5c 31 [2] 50 3b [2] 47 30 [2] 5c 7e [2] 61 }

  condition:
    any of them
}