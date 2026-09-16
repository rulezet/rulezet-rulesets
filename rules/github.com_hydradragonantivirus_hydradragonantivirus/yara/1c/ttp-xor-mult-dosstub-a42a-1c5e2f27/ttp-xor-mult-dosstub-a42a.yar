rule TTP_XOR_MULT_DOSStub_a42a {
  strings:
    $key_a42a = { f0 42 [2] 84 5a [2] c3 58 [2] 84 49 [2] ca 45 [2] c6 4f [2] d1 44 [2] ca 0a [2] f7 }

  condition:
    any of them
}