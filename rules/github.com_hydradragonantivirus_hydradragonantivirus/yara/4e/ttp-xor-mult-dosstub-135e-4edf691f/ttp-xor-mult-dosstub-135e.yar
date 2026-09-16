rule TTP_XOR_MULT_DOSStub_135e {
  strings:
    $key_135e = { 47 36 [2] 33 2e [2] 74 2c [2] 33 3d [2] 7d 31 [2] 71 3b [2] 66 30 [2] 7d 7e [2] 40 }

  condition:
    any of them
}