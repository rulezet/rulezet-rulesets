rule TTP_XOR_MULT_DOSStub_165e {
  strings:
    $key_165e = { 42 36 [2] 36 2e [2] 71 2c [2] 36 3d [2] 78 31 [2] 74 3b [2] 63 30 [2] 78 7e [2] 45 }

  condition:
    any of them
}