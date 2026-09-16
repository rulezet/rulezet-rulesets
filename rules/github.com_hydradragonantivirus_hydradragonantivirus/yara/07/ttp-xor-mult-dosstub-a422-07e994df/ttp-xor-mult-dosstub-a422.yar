rule TTP_XOR_MULT_DOSStub_a422 {
  strings:
    $key_a422 = { f0 4a [2] 84 52 [2] c3 50 [2] 84 41 [2] ca 4d [2] c6 47 [2] d1 4c [2] ca 02 [2] f7 }

  condition:
    any of them
}