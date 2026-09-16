rule TTP_XOR_MULT_DOSStub_fe76 {
  strings:
    $key_fe76 = { aa 1e [2] de 06 [2] 99 04 [2] de 15 [2] 90 19 [2] 9c 13 [2] 8b 18 [2] 90 56 [2] ad }

  condition:
    any of them
}