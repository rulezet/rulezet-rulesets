rule TTP_XOR_MULT_DOSStub_a4f4 {
  strings:
    $key_a4f4 = { f0 9c [2] 84 84 [2] c3 86 [2] 84 97 [2] ca 9b [2] c6 91 [2] d1 9a [2] ca d4 [2] f7 }

  condition:
    any of them
}