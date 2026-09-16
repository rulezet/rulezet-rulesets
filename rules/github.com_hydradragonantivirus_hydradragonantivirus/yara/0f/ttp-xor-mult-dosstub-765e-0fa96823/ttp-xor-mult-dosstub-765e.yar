rule TTP_XOR_MULT_DOSStub_765e {
  strings:
    $key_765e = { 22 36 [2] 56 2e [2] 11 2c [2] 56 3d [2] 18 31 [2] 14 3b [2] 03 30 [2] 18 7e [2] 25 }

  condition:
    any of them
}