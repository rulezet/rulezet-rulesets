rule TTP_XOR_MULT_DOSStub_a7e3 {
  strings:
    $key_a7e3 = { f3 8b [2] 87 93 [2] c0 91 [2] 87 80 [2] c9 8c [2] c5 86 [2] d2 8d [2] c9 c3 [2] f4 }

  condition:
    any of them
}