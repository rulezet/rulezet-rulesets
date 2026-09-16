rule TTP_XOR_MULT_DOSStub_a77d {
  strings:
    $key_a77d = { f3 15 [2] 87 0d [2] c0 0f [2] 87 1e [2] c9 12 [2] c5 18 [2] d2 13 [2] c9 5d [2] f4 }

  condition:
    any of them
}