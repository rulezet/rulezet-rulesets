rule TTP_XOR_MULT_DOSStub_a75e {
  strings:
    $key_a75e = { f3 36 [2] 87 2e [2] c0 2c [2] 87 3d [2] c9 31 [2] c5 3b [2] d2 30 [2] c9 7e [2] f4 }

  condition:
    any of them
}