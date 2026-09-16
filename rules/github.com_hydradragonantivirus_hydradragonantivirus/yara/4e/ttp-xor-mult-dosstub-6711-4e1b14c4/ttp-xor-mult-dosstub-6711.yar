rule TTP_XOR_MULT_DOSStub_6711 {
  strings:
    $key_6711 = { 33 79 [2] 47 61 [2] 00 63 [2] 47 72 [2] 09 7e [2] 05 74 [2] 12 7f [2] 09 31 [2] 34 }

  condition:
    any of them
}