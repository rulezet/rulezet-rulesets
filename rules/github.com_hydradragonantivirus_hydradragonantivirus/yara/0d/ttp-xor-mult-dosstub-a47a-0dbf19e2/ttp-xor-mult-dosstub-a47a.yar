rule TTP_XOR_MULT_DOSStub_a47a {
  strings:
    $key_a47a = { f0 12 [2] 84 0a [2] c3 08 [2] 84 19 [2] ca 15 [2] c6 1f [2] d1 14 [2] ca 5a [2] f7 }

  condition:
    any of them
}