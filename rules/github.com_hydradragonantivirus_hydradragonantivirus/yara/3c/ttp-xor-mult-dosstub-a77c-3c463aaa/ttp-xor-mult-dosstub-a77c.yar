rule TTP_XOR_MULT_DOSStub_a77c {
  strings:
    $key_a77c = { f3 14 [2] 87 0c [2] c0 0e [2] 87 1f [2] c9 13 [2] c5 19 [2] d2 12 [2] c9 5c [2] f4 }

  condition:
    any of them
}