rule TTP_XOR_MULT_DOSStub_eeb7 {
  strings:
    $key_eeb7 = { ba df [2] ce c7 [2] 89 c5 [2] ce d4 [2] 80 d8 [2] 8c d2 [2] 9b d9 [2] 80 97 [2] bd }

  condition:
    any of them
}