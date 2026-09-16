rule TTP_XOR_MULT_DOSStub_a710 {
  strings:
    $key_a710 = { f3 78 [2] 87 60 [2] c0 62 [2] 87 73 [2] c9 7f [2] c5 75 [2] d2 7e [2] c9 30 [2] f4 }

  condition:
    any of them
}