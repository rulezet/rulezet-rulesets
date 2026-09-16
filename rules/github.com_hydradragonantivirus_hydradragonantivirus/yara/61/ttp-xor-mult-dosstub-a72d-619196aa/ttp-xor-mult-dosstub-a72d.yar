rule TTP_XOR_MULT_DOSStub_a72d {
  strings:
    $key_a72d = { f3 45 [2] 87 5d [2] c0 5f [2] 87 4e [2] c9 42 [2] c5 48 [2] d2 43 [2] c9 0d [2] f4 }

  condition:
    any of them
}