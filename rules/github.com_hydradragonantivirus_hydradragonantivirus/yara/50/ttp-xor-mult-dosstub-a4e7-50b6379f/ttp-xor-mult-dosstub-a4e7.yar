rule TTP_XOR_MULT_DOSStub_a4e7 {
  strings:
    $key_a4e7 = { f0 8f [2] 84 97 [2] c3 95 [2] 84 84 [2] ca 88 [2] c6 82 [2] d1 89 [2] ca c7 [2] f7 }

  condition:
    any of them
}