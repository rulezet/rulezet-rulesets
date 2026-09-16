rule TTP_XOR_MULT_DOSStub_a15f {
  strings:
    $key_a15f = { f5 37 [2] 81 2f [2] c6 2d [2] 81 3c [2] cf 30 [2] c3 3a [2] d4 31 [2] cf 7f [2] f2 }

  condition:
    any of them
}