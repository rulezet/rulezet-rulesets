rule TTP_XOR_MULT_DOSStub_a4e5 {
  strings:
    $key_a4e5 = { f0 8d [2] 84 95 [2] c3 97 [2] 84 86 [2] ca 8a [2] c6 80 [2] d1 8b [2] ca c5 [2] f7 }

  condition:
    any of them
}