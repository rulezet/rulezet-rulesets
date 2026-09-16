rule TTP_XOR_MULT_DOSStub_a4f2 {
  strings:
    $key_a4f2 = { f0 9a [2] 84 82 [2] c3 80 [2] 84 91 [2] ca 9d [2] c6 97 [2] d1 9c [2] ca d2 [2] f7 }

  condition:
    any of them
}