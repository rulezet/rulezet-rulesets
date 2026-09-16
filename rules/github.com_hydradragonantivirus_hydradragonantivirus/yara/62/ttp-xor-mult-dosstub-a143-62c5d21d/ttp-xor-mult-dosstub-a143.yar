rule TTP_XOR_MULT_DOSStub_a143 {
  strings:
    $key_a143 = { f5 2b [2] 81 33 [2] c6 31 [2] 81 20 [2] cf 2c [2] c3 26 [2] d4 2d [2] cf 63 [2] f2 }

  condition:
    any of them
}