rule TTP_XOR_MULT_DOSStub_a75d {
  strings:
    $key_a75d = { f3 35 [2] 87 2d [2] c0 2f [2] 87 3e [2] c9 32 [2] c5 38 [2] d2 33 [2] c9 7d [2] f4 }

  condition:
    any of them
}