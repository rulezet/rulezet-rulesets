rule TTP_XOR_MULT_DOSStub_a47c {
  strings:
    $key_a47c = { f0 14 [2] 84 0c [2] c3 0e [2] 84 1f [2] ca 13 [2] c6 19 [2] d1 12 [2] ca 5c [2] f7 }

  condition:
    any of them
}