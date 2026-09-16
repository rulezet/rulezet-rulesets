rule TTP_XOR_MULT_DOSStub_c711 {
  strings:
    $key_c711 = { 93 79 [2] e7 61 [2] a0 63 [2] e7 72 [2] a9 7e [2] a5 74 [2] b2 7f [2] a9 31 [2] 94 }

  condition:
    any of them
}