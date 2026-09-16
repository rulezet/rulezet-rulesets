rule TTP_XOR_MULT_DOSStub_2711 {
  strings:
    $key_2711 = { 73 79 [2] 07 61 [2] 40 63 [2] 07 72 [2] 49 7e [2] 45 74 [2] 52 7f [2] 49 31 [2] 74 }

  condition:
    any of them
}