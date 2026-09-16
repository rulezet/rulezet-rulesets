rule TTP_XOR_MULT_DOSStub_a1f2 {
  strings:
    $key_a1f2 = { f5 9a [2] 81 82 [2] c6 80 [2] 81 91 [2] cf 9d [2] c3 97 [2] d4 9c [2] cf d2 [2] f2 }

  condition:
    any of them
}