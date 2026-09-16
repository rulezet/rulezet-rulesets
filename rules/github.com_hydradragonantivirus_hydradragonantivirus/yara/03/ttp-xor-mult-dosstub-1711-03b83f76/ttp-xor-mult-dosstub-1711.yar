rule TTP_XOR_MULT_DOSStub_1711 {
  strings:
    $key_1711 = { 43 79 [2] 37 61 [2] 70 63 [2] 37 72 [2] 79 7e [2] 75 74 [2] 62 7f [2] 79 31 [2] 44 }

  condition:
    any of them
}