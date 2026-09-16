rule TTP_XOR_MULT_DOSStub_a15e {
  strings:
    $key_a15e = { f5 36 [2] 81 2e [2] c6 2c [2] 81 3d [2] cf 31 [2] c3 3b [2] d4 30 [2] cf 7e [2] f2 }

  condition:
    any of them
}