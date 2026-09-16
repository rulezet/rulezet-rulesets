rule TTP_XOR_MULT_DOSStub_a45f {
  strings:
    $key_a45f = { f0 37 [2] 84 2f [2] c3 2d [2] 84 3c [2] ca 30 [2] c6 3a [2] d1 31 [2] ca 7f [2] f7 }

  condition:
    any of them
}