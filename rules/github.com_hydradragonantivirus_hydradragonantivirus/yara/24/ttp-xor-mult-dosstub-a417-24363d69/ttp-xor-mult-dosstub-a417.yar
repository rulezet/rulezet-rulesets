rule TTP_XOR_MULT_DOSStub_a417 {
  strings:
    $key_a417 = { f0 7f [2] 84 67 [2] c3 65 [2] 84 74 [2] ca 78 [2] c6 72 [2] d1 79 [2] ca 37 [2] f7 }

  condition:
    any of them
}