rule TTP_XOR_MULT_DOSStub_a1e5 {
  strings:
    $key_a1e5 = { f5 8d [2] 81 95 [2] c6 97 [2] 81 86 [2] cf 8a [2] c3 80 [2] d4 8b [2] cf c5 [2] f2 }

  condition:
    any of them
}