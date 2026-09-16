rule TTP_XOR_MULT_DOSStub_a711 {
  strings:
    $key_a711 = { f3 79 [2] 87 61 [2] c0 63 [2] 87 72 [2] c9 7e [2] c5 74 [2] d2 7f [2] c9 31 [2] f4 }

  condition:
    any of them
}