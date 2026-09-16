rule TTP_XOR_MULT_DOSStub_a1e3 {
  strings:
    $key_a1e3 = { f5 8b [2] 81 93 [2] c6 91 [2] 81 80 [2] cf 8c [2] c3 86 [2] d4 8d [2] cf c3 [2] f2 }

  condition:
    any of them
}