rule TTP_XOR_MULT_DOSStub_a44f {
  strings:
    $key_a44f = { f0 27 [2] 84 3f [2] c3 3d [2] 84 2c [2] ca 20 [2] c6 2a [2] d1 21 [2] ca 6f [2] f7 }

  condition:
    any of them
}